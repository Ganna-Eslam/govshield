"""
File masking / de-masking for CSV and XLSX.

Strategy (hybrid):
  1. Column-aware: if the header looks like name / national id / phone / address /
     password ... the WHOLE cell is replaced by a token (most reliable for tables).
  2. Content-aware: for every other column, the cell text goes through the
     existing detect() engine (+ an address recognizer) and only the sensitive
     spans are replaced.
  3. Fail-closed: if validation of a free-text cell fails, the whole cell is redacted.

The token -> original mapping is saved ENCRYPTED (Fernet) in a separate file.
"""
import csv
import io
import json
import os
import re
import secrets
import sys
from collections import Counter

_base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # privacy-engine/
for _sub in ("detection", "masking", "validation"):
    sys.path.insert(0, os.path.join(_base, _sub))

from base import Detection          # noqa: E402
from detect import detect, norm_ar  # noqa: E402
from validate import validate       # noqa: E402

TOKEN_RE = re.compile(r"\[\[[A-Z]+_[0-9A-F]{8}\]\]")
NULLISH = {"", "-", "--", "n/a", "na", "null", "none", "nan", "لا يوجد", "لايوجد"}
_OCR_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".pdf"}
VALID_TYPES = {"PERSON", "NID", "PHONE", "EMAIL", "CARD", "IBAN",
               "ADDRESS", "PASSWORD", "SKIP"}


# ---------------------------------------------------------------- headers
def _hnorm(s):
    """Normalize a header/keyword: lowercase, unify Arabic letters, drop 'ال' prefix."""
    s = norm_ar(str(s).lower()).replace("\u0649", "\u064a")
    s = re.sub(r"[^\w\u0600-\u06FF]+", " ", s.replace("_", " "))
    words = [w[2:] if w.startswith("\u0627\u0644") and len(w) > 4 else w for w in s.split()]
    return " ".join(words)


_RULES_RAW = [
    ("PASSWORD", ["password", "passwd", "pwd", "passcode", "pin", "secret", "token",
                  "apikey", "api key", "باسورد", "باسوورد", "كلمة المرور", "كلمة السر",
                  "كلمة سر", "رقم سري"]),
    ("EMAIL", ["email", "e mail", "mail", "ايميل", "بريد"]),
    ("NID", ["nid", "ssn", "national id", "nationalid", "national number", "id number",
             "id card", "رقم قومي", "قومي", "بطاقة", "هوية"]),
    ("CARD", ["card", "credit", "visa", "mastercard", "كارت", "فيزا", "ائتمان"]),
    ("IBAN", ["iban", "bank account", "account number", "acct", "حساب بنكي", "رقم حساب"]),
    ("PHONE", ["phone", "mobile", "tel", "telephone", "cell", "whatsapp", "تليفون",
               "هاتف", "موبايل", "موبيل", "جوال", "محمول", "واتساب"]),
    ("ADDRESS", ["address", "addr", "عنوان", "محل اقامة", "محل سكن", "اقامة"]),
    ("PERSON", ["name", "fullname", "full name", "first name", "last name", "firstname",
                "lastname", "surname", "username", "user name", "اسم", "عميل", "موظف",
                "مواطن", "مريض"]),
]
RULES = [(t, [_hnorm(k) for k in kws]) for t, kws in _RULES_RAW]


def classify_header(header, overrides=None):
    if header is None or not str(header).strip():
        return None
    h = _hnorm(header)
    if overrides and h in overrides:
        return overrides[h]
    words = set(h.split())
    for etype, kws in RULES:
        for kw in kws:
            if (" " in kw and kw in h) or kw in words:
                return etype
    return None


# ---------------------------------------------------------------- address recognizer
_W = r"[\u0621-\u064A\u0660-\u06690-9A-Za-z]+"
_AR_KW = (r"(?:شارع|ش(?=\s)|حي|ميدان|طريق|كورنيش|عمارة|عماره|برج|مدينة|مدينه|"
          r"قرية|قريه|محافظة|محافظه|منطقة|منطقه|عزبة|عزبه|نجع|كفر)")
AR_ADDRESS = re.compile(
    r"(?<![\u0621-\u064A])(?:(?:\d+|[\u0660-\u0669]+)\s+)?" + _AR_KW +
    r"\s+" + _W + r"(?:[\s,،\-]+" + _W + r"){0,5}")
EN_ADDRESS = re.compile(
    r"\b\d{1,5}\s+(?:[A-Za-z][A-Za-z.'-]*\s+){1,4}"
    r"(?:Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Lane|Ln)\b\.?", re.IGNORECASE)


def find_addresses(text):
    out = []
    for rx in (AR_ADDRESS, EN_ADDRESS):
        for m in rx.finditer(text):
            out.append(Detection("ADDRESS", m.start(), m.end(), m.group(), 0.8, "regex"))
    return out


STRUCTURED = {"NID", "PHONE", "EMAIL", "CARD", "IBAN", "SECRET"}


def _trim_addresses(dets, text):
    """An address span must never swallow a structured value (e.g. the phone after it)."""
    structured = [d for d in dets if d.type in STRUCTURED]
    keep = []
    for d in dets:
        if d.type == "ADDRESS":
            for s in structured:
                if s.start < d.end and s.end > d.start:
                    if s.start > d.start:
                        d.end = s.start
                    else:
                        d.start = s.end
            while d.end > d.start and text[d.end - 1].isspace():
                d.end -= 1
            d.value = text[d.start:d.end]
            if not d.value.strip():
                continue
        keep.append(d)
    return keep


def _resolve(dets, text):
    """Merge overlapping detections into non-overlapping spans (union, fail-closed)."""
    dets = _trim_addresses(dets, text)
    dets = sorted(dets, key=lambda d: (d.start, -(d.end - d.start), -d.confidence))
    out = []
    for d in dets:
        if out and d.start < out[-1].end:
            if d.end > out[-1].end:
                out[-1].end = d.end
                out[-1].value = text[out[-1].start:out[-1].end]
            continue
        out.append(d)
    return out


# ---------------------------------------------------------------- tokens
class TokenVault:
    """Same (type, value) -> same token inside one file. Mapping stays local."""

    def __init__(self):
        self.mapping = {}
        self._by_value = {}

    def token_for(self, etype, value):
        key = (etype, value)
        if key not in self._by_value:
            while True:
                tok = f"[[{etype}_{secrets.token_hex(4).upper()}]]"
                if tok not in self.mapping:
                    break
            self._by_value[key] = tok
            self.mapping[tok] = value
        return self._by_value[key]


# ---------------------------------------------------------------- cell logic
def _to_text(v):
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() else repr(v)
    if isinstance(v, str):
        return v
    return None  # dates etc. are left untouched


def mask_free_text(text, vault):
    """Mask sensitive spans inside free text. Returns (new_text, [types])."""
    dets = _resolve(detect(text) + find_addresses(text), text)
    if not dets:
        return text, []
    local, out = {}, text
    for d in sorted(dets, key=lambda d: d.start, reverse=True):
        tok = vault.token_for(d.type, d.value)
        local[tok] = d.value
        out = out[:d.start] + tok + out[d.end:]
    ok, _ = validate(out, local)
    if not ok:  # fail-closed: redact the entire cell
        return vault.token_for("REDACTED", text), ["REDACTED"]
    return out, [d.type for d in dets]


def _make_mask_fn(vault, stats):
    def fn(sheet, header, col_type, value):
        text = _to_text(value)
        if text is None or text.strip().lower() in NULLISH or col_type == "SKIP":
            return value
        if col_type:
            stats[(sheet, header, col_type)] += 1
            return vault.token_for(col_type, text)
        new, types = mask_free_text(text, vault)
        for t in types:
            stats[(sheet, header, t)] += 1
        return new if types else value
    return fn


def _make_unmask_fn(mapping, stats):
    def fn(sheet, header, col_type, value):
        if not isinstance(value, str) or "[[" not in value:
            return value

        def sub(m):
            tok = m.group(0)
            if tok in mapping:
                stats[("restored",)] += 1
                return mapping[tok]
            stats[("unknown_token",)] += 1
            return tok
        return TOKEN_RE.sub(sub, value)
    return fn


# ---------------------------------------------------------------- file I/O
def _process_csv(src, dst, fn, header_row, overrides):
    raw = open(src, "rb").read()
    for enc in ("utf-8-sig", "cp1256"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise ValueError("Cannot decode CSV (tried utf-8 and cp1256)")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text, newline=""), dialect))
    if not rows:
        raise ValueError("Empty file")

    types = []
    out = []
    for i, row in enumerate(rows, start=1):
        if i < header_row:
            out.append([fn("csv", None, None, c) for c in row])
        elif i == header_row:
            types = [classify_header(h, overrides) for h in row]
            out.append(row)
        else:
            new = []
            for j, c in enumerate(row):
                t = types[j] if j < len(types) else None
                h = rows[header_row - 1][j] if j < len(types) else None
                new.append(fn("csv", h, t, c))
            out.append(new)

    with open(dst, "w", encoding="utf-8-sig", newline="") as f:  # BOM so Excel shows Arabic
        csv.writer(f, delimiter=dialect.delimiter).writerows(out)


def _process_xlsx(src, dst, fn, header_row, overrides, stats):
    from openpyxl import load_workbook
    wb = load_workbook(src)
    for ws in wb.worksheets:
        headers = [c.value for c in ws[header_row]] if ws.max_row >= header_row else []
        types = [classify_header(h, overrides) for h in headers]
        for row in ws.iter_rows(min_row=1):
            for cell in row:
                if type(cell).__name__ == "MergedCell":
                    continue
                if cell.data_type == "f":
                    stats[("formula_cells_skipped",)] += 1
                    continue
                if cell.row == header_row:
                    continue
                idx = cell.column - 1
                t = types[idx] if (cell.row > header_row and idx < len(types)) else None
                h = headers[idx] if (cell.row > header_row and idx < len(headers)) else None
                cell.value = fn(ws.title, h, t, cell.value)
    wb.save(dst)


def process_file(src, dst, fn, stats, header_row=1, overrides=None):
    ext = os.path.splitext(src)[1].lower()
    if os.path.abspath(src) == os.path.abspath(dst):
        raise ValueError("Output path must differ from input path")
    if ext in (".csv", ".tsv", ".txt"):
        _process_csv(src, dst, fn, header_row, overrides)
    elif ext == ".xlsx":
        _process_xlsx(src, dst, fn, header_row, overrides, stats)
    else:
        raise ValueError("Unsupported file type. Use .csv or .xlsx (save .xls as .xlsx first)")


# ---------------------------------------------------------------- encrypted mapping
def _fernet(key_file, create):
    from cryptography.fernet import Fernet
    if os.path.exists(key_file):
        key = open(key_file, "rb").read().strip()
    elif create:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        raise FileNotFoundError(f"Key file not found: {key_file}")
    return Fernet(key)


def save_mapping(mapping, map_file, key_file):
    data = json.dumps(mapping, ensure_ascii=False).encode("utf-8")
    with open(map_file, "wb") as f:
        f.write(_fernet(key_file, create=True).encrypt(data))


def load_mapping(map_file, key_file):
    from cryptography.fernet import InvalidToken
    token = open(map_file, "rb").read()
    try:
        return json.loads(_fernet(key_file, create=False).decrypt(token).decode("utf-8"))
    except InvalidToken:
        raise ValueError("Wrong key for this mapping file")


# ---------------------------------------------------------------- public API
def mask_file(src, dst, map_file=None, key_file=None, header_row=1, overrides=None):
    if os.path.splitext(src)[1].lower() in _OCR_EXTS:
        # images / scanned PDFs: OCR + irreversible redaction, no mapping or key file
        from ocr_engine import protect_file
        return protect_file(src, dst)
    map_file = map_file or dst + ".map.enc"
    key_file = key_file or dst + ".key"
    overrides = {_hnorm(k): v.upper() for k, v in (overrides or {}).items()}
    bad = set(overrides.values()) - VALID_TYPES
    if bad:
        raise ValueError(f"Invalid type(s) {bad}. Valid: {sorted(VALID_TYPES)}")

    vault, stats = TokenVault(), Counter()
    process_file(src, dst, _make_mask_fn(vault, stats), stats, header_row, overrides)
    save_mapping(vault.mapping, map_file, key_file)
    return {"output": dst, "map_file": map_file, "key_file": key_file,
            "unique_tokens": len(vault.mapping), "stats": stats}


def unmask_file(src, dst, map_file=None, key_file=None, header_row=1):
    if os.path.splitext(src)[1].lower() in _OCR_EXTS:
        raise ValueError("Images and scanned PDFs are masked irreversibly; there is nothing to restore")
    map_file = map_file or src + ".map.enc"
    key_file = key_file or src + ".key"
    mapping = load_mapping(map_file, key_file)
    stats = Counter()
    process_file(src, dst, _make_unmask_fn(mapping, stats), stats, header_row)
    return {"output": dst, "stats": stats}
