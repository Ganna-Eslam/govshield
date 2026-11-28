"""
OCR protection for images and scanned PDFs.

Flow (per image / page):
  1. Normalise the image (EXIF rotation, size limits).
  2. OCR with Tesseract (ara+eng), two passes with different preprocessing.
  3. Run the SAME detection used for text/CSV/XLSX on the recognised text.
  4. Map each detection back to word boxes and paint them over (irreversible).
     Words recognised with low confidence are painted too (fail-closed).
  5. Re-encode the pixels from scratch (drops EXIF / metadata) and re-OCR the
     result. If anything sensitive can still be read, the file is blocked.

Anything that cannot be completed or verified raises OcrBlocked, and no output
file is left behind. Image masking is irreversible: there is no mapping file.
Nothing here ever logs or returns recognised text or detected values.
"""
import io
import os
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass

from PIL import Image, ImageDraw, ImageOps

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from file_masker import _resolve, find_addresses  # noqa: E402
from detect import detect  # noqa: E402

IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"}
PDF_EXTS = {".pdf"}
OCR_EXTS = IMAGE_EXTS | PDF_EXTS

LANGS = os.environ.get("GOVSHIELD_OCR_LANGS", "ara+eng")
MIN_WORD_CONF = float(os.environ.get("GOVSHIELD_OCR_MIN_CONF", "50"))       # below: paint anyway
MIN_PAGE_CONF = float(os.environ.get("GOVSHIELD_OCR_MIN_PAGE_CONF", "40"))  # below: block page
MAX_PIXELS = int(os.environ.get("GOVSHIELD_OCR_MAX_PIXELS", str(40_000_000)))
MAX_PAGES = int(os.environ.get("GOVSHIELD_OCR_MAX_PAGES", "30"))
TIMEOUT = int(os.environ.get("GOVSHIELD_OCR_TIMEOUT", "90"))                # seconds per OCR call
PDF_DPI = int(os.environ.get("GOVSHIELD_OCR_PDF_DPI", "250"))
ALLOW_NO_TEXT = os.environ.get("GOVSHIELD_OCR_ALLOW_NO_TEXT", "0") == "1"
PASSES = ("gray_psm3", "binary_psm6")

Image.MAX_IMAGE_PIXELS = MAX_PIXELS


class OcrBlocked(Exception):
    """Protection could not be completed or verified. Reason contains no content."""


@dataclass
class Word:
    text: str
    left: int
    top: int
    width: int
    height: int
    conf: float
    start: int = 0   # character span inside the page text
    end: int = 0


# ---------------------------------------------------------------- setup
def _configure():
    import pytesseract
    cmd = os.environ.get("GOVSHIELD_TESSERACT_CMD")
    if cmd:
        pytesseract.pytesseract.tesseract_cmd = cmd
    tessdata = os.environ.get("GOVSHIELD_TESSDATA")
    if tessdata:
        os.environ["TESSDATA_PREFIX"] = tessdata
    return pytesseract


def ocr_ready():
    """(ok, reason). Used by the service /ready check and by the tests."""
    try:
        pt = _configure()
        have = set(pt.get_languages(config=""))
    except Exception:
        return False, "tesseract not available"
    missing = [l for l in LANGS.split("+") if l not in have]
    if missing:
        return False, f"missing OCR language data: {','.join(missing)}"
    return True, "ok"


# ---------------------------------------------------------------- image handling
def _load_image(path):
    try:
        with Image.open(path) as im:
            im.verify()
        im = Image.open(path)
        if getattr(im, "n_frames", 1) > 1:
            raise OcrBlocked("multi-frame image not supported")
        im = ImageOps.exif_transpose(im)
        if im.width * im.height > MAX_PIXELS:
            raise OcrBlocked("image too large")
        if im.mode in ("RGBA", "LA", "P"):
            im = im.convert("RGBA")
            bg = Image.new("RGB", im.size, (255, 255, 255))
            bg.paste(im, mask=im.split()[-1])
            im = bg
        return im.convert("RGB")
    except OcrBlocked:
        raise
    except Image.DecompressionBombError:
        raise OcrBlocked("image too large")
    except Exception:
        raise OcrBlocked("unreadable or corrupt image")


def _prepare(img, kind):
    """Returns (image for OCR, scale factor to original coordinates)."""
    g = ImageOps.autocontrast(img.convert("L"))
    longest = max(g.size)
    scale = 1.0
    if longest < 2000:
        scale = min(3.0, 2000 / longest)
    elif longest > 5000:
        scale = 5000 / longest
    if scale != 1.0:
        g = g.resize((max(1, int(g.width * scale)), max(1, int(g.height * scale))), Image.LANCZOS)
    if kind.startswith("binary"):
        mean = sum(i * c for i, c in enumerate(g.histogram())) / max(1, g.width * g.height)
        g = g.point(lambda p, t=mean * 0.9: 255 if p > t else 0)
    return g, scale


def _ocr_words(img, kind):
    pt = _configure()
    prepared, scale = _prepare(img, kind)
    psm = 6 if kind.endswith("psm6") else 3
    try:
        data = pt.image_to_data(prepared, lang=LANGS, config=f"--psm {psm}",
                                output_type=pt.Output.DICT, timeout=TIMEOUT)
    except Exception:
        raise OcrBlocked("OCR failed or timed out")
    words, lines = [], {}
    for i, txt in enumerate(data["text"]):
        txt = (txt or "").strip()
        try:
            conf = float(data["conf"][i])
        except (TypeError, ValueError):
            conf = -1.0
        if not txt or conf < 0:
            continue
        w = Word(txt, int(data["left"][i] / scale), int(data["top"][i] / scale),
                 max(1, int(data["width"][i] / scale)), max(1, int(data["height"][i] / scale)), conf)
        key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        lines.setdefault(key, []).append(w)
        words.append(w)
    return list(lines.values())


def _build_text(lines):
    """Join words into page text and remember each word's character span."""
    parts, pos = [], 0
    for ln in lines:
        for j, w in enumerate(ln):
            if j:
                parts.append(" ")
                pos += 1
            w.start, w.end = pos, pos + len(w.text)
            parts.append(w.text)
            pos = w.end
        parts.append("\n")
        pos += 1
    return "".join(parts)


def _sensitive_boxes(lines):
    """-> (boxes, Counter of types, mean confidence, word count)."""
    text = _build_text(lines)
    words = [w for ln in lines for w in ln]
    if not words:
        return [], Counter(), 0.0, 0
    dets = _resolve(detect(text) + find_addresses(text), text)
    boxes, types = [], Counter()
    flagged = set()
    for d in dets:
        types[d.type] += 1
        for i, w in enumerate(words):
            if w.start < d.end and w.end > d.start:
                flagged.add(i)
    for i, w in enumerate(words):
        if i in flagged or w.conf < MIN_WORD_CONF:
            boxes.append(w)
            if i not in flagged:
                types["LOW_CONFIDENCE"] += 1
    mean_conf = sum(w.conf for w in words) / len(words)
    return boxes, types, mean_conf, len(words)


def _paint(img, boxes):
    out = img.copy()
    draw = ImageDraw.Draw(out)
    for w in boxes:
        pad = max(3, int(w.height * 0.2))
        draw.rectangle([w.left - pad, w.top - pad, w.left + w.width + pad, w.top + w.height + pad],
                       fill=(0, 0, 0))
    return out


def _clean_copy(img):
    """New image object built from pixels only, so no EXIF / info survives."""
    clean = Image.new("RGB", img.size)
    clean.putdata(list(img.getdata()))
    return clean


def protect_image_obj(img):
    """Protect one PIL image. Returns (protected image, Counter of types)."""
    all_boxes, types = [], Counter()
    total_words, best_conf = 0, 0.0
    for kind in PASSES:
        lines = _ocr_words(img, kind)
        boxes, t, mean_conf, n = _sensitive_boxes(lines)
        all_boxes += boxes
        total_words = max(total_words, n)
        best_conf = max(best_conf, mean_conf)
        for k, v in t.items():
            types[k] = max(types[k], v)   # same item seen by both passes counts once
    if total_words == 0:
        if ALLOW_NO_TEXT:
            return _clean_copy(img), types
        raise OcrBlocked("no readable text found (cannot verify)")
    if best_conf < MIN_PAGE_CONF:
        raise OcrBlocked("text too unclear to verify")

    protected = _clean_copy(_paint(img, all_boxes))

    # verification: read the result again, nothing sensitive may remain
    for kind in PASSES:
        lines = _ocr_words(protected, kind)
        text = _build_text(lines)
        if detect(text) or find_addresses(text):
            raise OcrBlocked("sensitive pattern still readable after protection")
    return protected, types


# ---------------------------------------------------------------- files
def _save_image(img, dst):
    ext = os.path.splitext(dst)[1].lower()
    if ext in (".jpg", ".jpeg"):
        img.save(dst, "JPEG", quality=95, optimize=True)
    elif ext in (".tif", ".tiff"):
        img.save(dst, "TIFF")
    elif ext == ".bmp":
        img.save(dst, "BMP")
    else:
        img.save(dst, "PNG")


def _pdf_pages(src):
    import pymupdf
    try:
        doc = pymupdf.open(src)
    except Exception:
        raise OcrBlocked("unreadable or corrupt PDF")
    try:
        if doc.needs_pass or doc.is_encrypted:
            raise OcrBlocked("encrypted PDF not supported")
        if doc.page_count == 0:
            raise OcrBlocked("empty PDF")
        if doc.page_count > MAX_PAGES:
            raise OcrBlocked("too many pages")
        for page in doc:
            pix = page.get_pixmap(dpi=PDF_DPI, alpha=False)
            if pix.width * pix.height > MAX_PIXELS:
                raise OcrBlocked("page too large")
            img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
            yield img, page.rect.width, page.rect.height
    finally:
        doc.close()


def _protect_pdf(src, dst):
    import pymupdf
    out = pymupdf.open()
    stats = Counter()
    try:
        for n, (img, w_pt, h_pt) in enumerate(_pdf_pages(src), 1):
            protected, types = protect_image_obj(img)
            for t, c in types.items():
                stats[(f"p{n}", "image", t)] += c
            buf = io.BytesIO()
            protected.save(buf, "PNG")
            page = out.new_page(width=w_pt, height=h_pt)
            page.insert_image(page.rect, stream=buf.getvalue())
        out.set_metadata({})
        out.del_xml_metadata()
        out.save(dst, garbage=4, deflate=True)
    finally:
        out.close()
    return stats


def protect_file(src, dst):
    """Protect an image or scanned PDF. On any failure raises OcrBlocked and leaves no output."""
    ext = os.path.splitext(src)[1].lower()
    if ext not in OCR_EXTS:
        raise OcrBlocked("unsupported file type")
    if os.path.abspath(src) == os.path.abspath(dst):
        raise ValueError("Output path must differ from input path")
    ok, reason = ocr_ready()
    if not ok:
        raise OcrBlocked(reason)

    fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(dst)[1], dir=os.path.dirname(os.path.abspath(dst)))
    os.close(fd)
    try:
        if ext in PDF_EXTS:
            stats = _protect_pdf(src, tmp)
        else:
            protected, types = protect_image_obj(_load_image(src))
            stats = Counter({("p1", "image", t): c for t, c in types.items()})
            _save_image(protected, tmp)
        os.replace(tmp, dst)
    except OcrBlocked:
        raise
    except Exception:
        raise OcrBlocked("protection failed")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return {"output": dst, "map_file": None, "key_file": None, "unique_tokens": 0,
            "stats": stats, "reversible": False}
