"""
GOVSHIELD - Streamlit GUI for the masking / de-masking pipeline.

Run from the project root:
    streamlit run app.py
"""
import html
import io
import os
import re
import sys
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

# ------------------------------------------------------------------ engine imports
ROOT = Path(__file__).resolve().parent
for _p in (ROOT / "privacy-engine", ROOT / "privacy-engine" / "detection",
           ROOT / "privacy-engine" / "masking", ROOT / "privacy-engine" / "validation",
           ROOT / "privacy-engine" / "files"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import detect as detect_mod            # noqa: E402
from detect import detect              # noqa: E402
from ner import NerRecognizer          # noqa: E402
from mask import mask, restore         # noqa: E402
from validate import validate          # noqa: E402
import file_masker                     # noqa: E402

TOKEN_RE = re.compile(r"\[\[[A-Z]+_[0-9A-F]+\]\]")
OVERRIDE_OPTIONS = ["AUTO", "SKIP", "PERSON", "NID", "PHONE", "EMAIL",
                    "ADDRESS", "PASSWORD", "CARD", "IBAN"]
COLORS = {"PERSON": "#ffd54f", "NID": "#ff8a80", "PHONE": "#80d8ff", "EMAIL": "#b9f6ca",
          "CARD": "#ea80fc", "IBAN": "#ccff90", "SECRET": "#ff5252", "ADDRESS": "#ffab91"}
MIME = {".csv": "text/csv",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
PLACEHOLDER = "— choose an example —"
SAMPLES = [
    "حلل شكوى أحمد محمد، رقمه القومي 29012345678901، وتليفونه 01012345678",
    "كلمني على +201112345678 أو ahmed@gmail.com",
    "الرقم القومي ٢٩٠١٢٣٤٥٦٧٨٩٠١ والموبايل ٠١٠١٢٣٤٥٦٧٨",
    "المهندس كريم قال إن الموظفة منى اتأخرت",
    "العميل ساكن في 12 شارع التحرير الدقي الجيزة وموبايله 010-1234-5678",
    "الكارت 4111 1111 1111 1111 والحساب GB82 WEST 1234 5698 7654 32",
    "Dr. Mahmoud Abdelrahman approved the request, contact m.abdelrahman@example.com",
    "password: Hunter2xyz",
]
SAMPLE_HEADER = ["الاسم", "الرقم القومي", "رقم الموبايل", "العنوان", "كلمة المرور", "ملاحظات", "المرتب"]
SAMPLE_ROWS = [
    ["أحمد محمد", "29012345678901", "01012345678", "12 شارع التحرير، الدقي، الجيزة",
     "Hunter2xyz", "كلمني على ahmed@gmail.com", "5000"],
    ["منى سيد", "29512345678901", "010 1234 5679", "برج النيل كورنيش المعادي",
     "P@ss-123", "العميل ساكن في شارع الهرم", "7000"],
    ["كريم علي", "29812345678901", "01234567890", "5 ش الجمهورية المنصورة",
     "abc12345", "مفيش ملاحظات", "6000"],
]


# ================================================================== engine helpers
def apply_engine_settings(use_ner, strict_names, packs):
    """Toggle engine options at runtime (instead of environment variables)."""
    for r in detect_mod.REGISTRY:
        if isinstance(r, NerRecognizer):
            if not hasattr(r, "_orig_model"):
                r._orig_model = r.model_name
            r.model_name = r._orig_model if use_ner else "none"
    detect_mod.STRICT_NAMES = strict_names
    detect_mod.ENABLED_PACKS = set(packs) | {"core"}


def run_pipeline(text, with_address=True):
    """
    Step-by-step version of pipeline.protect() so every stage can be shown in the GUI.
    Same rules: secrets are blocked, any failure is fail-closed.
    """
    steps, dets = [], []
    try:
        dets = detect(text)
        if with_address:
            dets = file_masker._resolve(dets + file_masker.find_addresses(text), text)
        steps.append(("1. Detect", True, f"{len(dets)} sensitive item(s) found"))

        if any(d.type == "SECRET" for d in dets):
            steps.append(("2. Policy check", False, "Secret detected -> blocked (never tokenized)"))
            return {"status": "blocked", "reason": "secret detected", "steps": steps, "dets": dets}
        steps.append(("2. Policy check", True, "No secrets"))

        safe, mapping = mask(text, dets)
        steps.append(("3. Mask", True, f"{len(mapping)} unique token(s) created"))

        ok, reason = validate(safe, mapping)
        if not ok:
            steps.append(("4. Validate", False, reason))
            return {"status": "blocked", "reason": reason, "steps": steps, "dets": dets}
        steps.append(("4. Validate", True, "Nothing sensitive left in the output"))
        return {"status": "protected", "safe_text": safe, "mapping": mapping,
                "steps": steps, "dets": dets}
    except Exception as e:  # fail-closed
        steps.append(("Error", False, str(e)))
        return {"status": "blocked", "reason": f"error: {e}", "steps": steps, "dets": dets}


def highlight(text, dets):
    out, pos = [], 0
    for d in sorted(dets, key=lambda d: d.start):
        if d.start < pos:
            continue
        out.append(html.escape(text[pos:d.start]))
        c = COLORS.get(d.type, "#eee")
        out.append(f'<mark style="background:{c};color:#000;padding:0 4px;border-radius:4px">'
                   f'{html.escape(text[d.start:d.end])} <sub>{d.type}</sub></mark>')
        pos = d.end
    out.append(html.escape(text[pos:]))
    return ('<div dir="auto" style="line-height:2;white-space:pre-wrap;font-size:1.05rem">'
            + "".join(out) + "</div>")


def plain_box(text):
    return ('<div dir="auto" style="line-height:2;white-space:pre-wrap;font-size:1.05rem">'
            + html.escape(text) + "</div>")


# ================================================================== file helpers
def read_preview(data: bytes, ext: str, header_row: int = 1) -> dict:
    """Return {sheet_name: DataFrame(str)} for a CSV / XLSX given as bytes."""
    h = header_row - 1
    if ext == ".xlsx":
        sheets = pd.read_excel(io.BytesIO(data), sheet_name=None, dtype=str, header=h)
        return {k: v.fillna("") for k, v in sheets.items()}
    for enc in ("utf-8-sig", "cp1256"):
        try:
            df = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False,
                             sep=None, engine="python", encoding=enc, header=h)
            return {"data": df}
        except UnicodeDecodeError:
            continue
    raise ValueError("Cannot decode the CSV file (tried utf-8 and cp1256)")


def same_content(a: dict, b: dict) -> bool:
    if list(a) != list(b):
        return False
    return all(a[k].astype(str).reset_index(drop=True)
               .equals(b[k].astype(str).reset_index(drop=True)) for k in a)


def mask_bytes(data: bytes, ext: str, header_row: int, overrides: dict) -> dict:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        src, dst = os.path.join(tmp, "input" + ext), os.path.join(tmp, "masked" + ext)
        with open(src, "wb") as f:
            f.write(data)
        r = file_masker.mask_file(src, dst, header_row=header_row, overrides=overrides)
        read = lambda p: open(p, "rb").read()  # noqa: E731
        return {"masked": read(dst), "map": read(r["map_file"]), "key": read(r["key_file"]),
                "stats": r["stats"], "tokens": r["unique_tokens"]}


def unmask_bytes(masked: bytes, map_b: bytes, key_b: bytes, ext: str, header_row: int) -> dict:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        src, dst = os.path.join(tmp, "masked" + ext), os.path.join(tmp, "restored" + ext)
        mp, kp = os.path.join(tmp, "m.map.enc"), os.path.join(tmp, "m.key")
        for path, content in ((src, masked), (mp, map_b), (kp, key_b)):
            with open(path, "wb") as f:
                f.write(content)
        r = file_masker.unmask_file(src, dst, map_file=mp, key_file=kp, header_row=header_row)
        with open(dst, "rb") as f:
            return {"restored": f.read(), "stats": r["stats"]}


def stats_table(stats) -> pd.DataFrame:
    rows = [{"Sheet": k[0], "Column": k[1] if k[1] is not None else "(above header)",
             "Type": k[2], "Cells masked": n} for k, n in stats.items() if len(k) == 3]
    return pd.DataFrame(rows)


def show_sheets(sheets: dict, max_rows=50):
    def one(df):
        st.dataframe(df.head(max_rows))
        if len(df) > max_rows:
            st.caption(f"Showing first {max_rows} of {len(df)} rows")
    if len(sheets) == 1:
        one(next(iter(sheets.values())))
    else:
        for tab, (name, df) in zip(st.tabs(list(sheets)), sheets.items()):
            with tab:
                one(df)


def sample_csv_bytes():
    buf = io.StringIO()
    import csv
    csv.writer(buf).writerows([SAMPLE_HEADER] + SAMPLE_ROWS)
    return buf.getvalue().encode("utf-8-sig")


def sample_xlsx_bytes():
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Employees"
    ws.append(SAMPLE_HEADER)
    for r in SAMPLE_ROWS:
        ws.append(r)
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


# ================================================================== callbacks
def _load_sample():
    if st.session_state.sample != PLACEHOLDER:
        st.session_state.input_text = st.session_state.sample


def _load_txt():
    f = st.session_state.get("txt_upload")
    if f is None:
        return
    raw = f.getvalue()
    for enc in ("utf-8-sig", "cp1256"):
        try:
            st.session_state.input_text = raw.decode(enc)
            return
        except UnicodeDecodeError:
            continue


def _mask_text():
    text = st.session_state.input_text
    if not text.strip():
        st.session_state.text_result = None
        return
    res = run_pipeline(text, st.session_state.get("with_address", True))
    res["original"] = text
    st.session_state.text_result = res
    if res["status"] == "protected":
        st.session_state.mapping.update(res["mapping"])
        # Simulated AI reply that still contains the tokens
        st.session_state.ai_reply = "Summary from the AI:\n" + res["safe_text"]


def _clear_session():
    for k in ("mapping", "text_result", "text_restored", "ai_reply", "file_result", "file_restored"):
        st.session_state.pop(k, None)
    st.session_state.mapping = {}


# ================================================================== UI: text tab
def tab_text():
    st.subheader("Text: mask -> (send to AI) -> de-mask")
    c1, c2 = st.columns(2)
    c1.selectbox("Load an example", [PLACEHOLDER] + SAMPLES, key="sample", on_change=_load_sample)
    c2.file_uploader("...or upload a .txt file", type=["txt"], key="txt_upload", on_change=_load_txt)

    st.text_area("Input text (type or paste)", key="input_text", height=130)
    st.button("1) Mask text", type="primary", on_click=_mask_text)

    res = st.session_state.get("text_result")
    if res:
        st.markdown("#### Pipeline steps")
        for name, ok, note in res["steps"]:
            (st.success if ok else st.error)(f"**{name}** - {note}")

        left, right = st.columns(2)
        with left:
            st.markdown("**Original (detections highlighted)**")
            st.markdown(highlight(res["original"], res["dets"]), unsafe_allow_html=True)
        with right:
            if res["status"] == "protected":
                st.markdown("**Safe text (what is allowed to leave your machine)**")
                st.markdown(plain_box(res["safe_text"]), unsafe_allow_html=True)
                with st.expander("Copy-friendly version"):
                    st.code(res["safe_text"], language=None)
            else:
                st.error(f"BLOCKED - outbound not allowed. Reason: {res['reason']}")

        if res["dets"]:
            show_vals = st.checkbox("Show original values in the table (local screen only)", value=True)
            st.dataframe(pd.DataFrame([{
                "Type": d.type, **({"Value": d.value} if show_vals else {}),
                "Confidence": round(d.confidence, 2), "Source": d.source,
                "Start": d.start, "End": d.end} for d in res["dets"]]))

    st.divider()
    st.markdown("#### 2) De-mask the AI response")
    st.caption(f"Tokens kept in this session's memory: {len(st.session_state.mapping)} "
               "(RAM only, never sent anywhere).")
    st.text_area("AI response that contains tokens (edit freely to simulate a real reply)",
                 key="ai_reply", height=130)
    if st.button("De-mask response"):
        reply = st.session_state.ai_reply
        mapping = st.session_state.mapping
        found = TOKEN_RE.findall(reply)
        st.session_state.text_restored = {
            "text": restore(reply, mapping),
            "known": sorted({t for t in found if t in mapping}),
            "unknown": sorted({t for t in found if t not in mapping}),
        }
    r = st.session_state.get("text_restored")
    if r:
        st.markdown("**Restored text**")
        st.markdown(plain_box(r["text"]), unsafe_allow_html=True)
        st.caption(f"Tokens restored: {len(r['known'])}")
        if r["unknown"]:
            st.warning(f"{len(r['unknown'])} token(s) not found in this session's mapping "
                       "(left as-is): " + ", ".join(r["unknown"]))


# ================================================================== UI: file tab
def tab_file():
    st.subheader("Files (CSV / Excel): mask -> download -> de-mask")
    with st.expander("No file handy? Download a sample"):
        a, b = st.columns(2)
        a.download_button("sample people.csv", sample_csv_bytes(), "people.csv", "text/csv")
        b.download_button("sample people.xlsx", sample_xlsx_bytes(), "people.xlsx", MIME[".xlsx"])

    up = st.file_uploader("Upload a CSV or Excel file", type=["csv", "xlsx"], key="file_upload")
    if up is None:
        st.info("Upload a file to start.")
        return

    file_id = f"{up.name}-{up.size}"
    if st.session_state.get("file_id") != file_id:
        st.session_state.file_id = file_id
        st.session_state.pop("file_result", None)
        st.session_state.pop("file_restored", None)

    ext = Path(up.name).suffix.lower()
    stem = Path(up.name).stem
    data = up.getvalue()
    header_row = st.number_input("Header row (the row that contains column names)",
                                 min_value=1, value=1, step=1)
    try:
        orig = read_preview(data, ext, header_row)
    except Exception as e:
        st.error(f"Could not read the file: {e}")
        return

    st.markdown("#### Original file (local preview)")
    show_sheets(orig)

    # ---- column settings
    headers = []
    for df in orig.values():
        for h in df.columns:
            if str(h) not in headers:
                headers.append(str(h))
    st.markdown("#### Column settings")
    st.caption("The tool guesses each column type from its header. Change **Override** if a guess "
               "is wrong: `SKIP` = do not touch the column, or force a type such as `NID`.")
    cols_df = pd.DataFrame({
        "Column": headers,
        "Auto-detected": [file_masker.classify_header(h) or "content scan" for h in headers],
        "Override": ["AUTO"] * len(headers)})
    edited = st.data_editor(
        cols_df, hide_index=True, disabled=["Column", "Auto-detected"], key=f"cols_{file_id}_{header_row}",
        column_config={"Override": st.column_config.SelectboxColumn(options=OVERRIDE_OPTIONS, required=True)})
    overrides = {r["Column"]: r["Override"] for _, r in edited.iterrows() if r["Override"] != "AUTO"}

    # ---- mask
    if st.button("1) Mask file", type="primary"):
        with st.spinner("Masking... (the first run with NER loads the models)"):
            try:
                res = mask_bytes(data, ext, header_row, overrides)
                res.update(ext=ext, stem=stem, original=orig, header_row=header_row)
                st.session_state.file_result = res
                st.session_state.pop("file_restored", None)
            except Exception as e:
                st.session_state.pop("file_result", None)
                st.error(f"Masking failed: {e}")

    res = st.session_state.get("file_result")
    if res:
        st.success(f"Done. {res['tokens']} unique token(s) created.")
        st.markdown("#### What was masked")
        tbl = stats_table(res["stats"])
        st.dataframe(tbl) if len(tbl) else st.info("Nothing sensitive was detected.")
        for k, n in res["stats"].items():
            if len(k) == 1:
                st.warning(f"{k[0].replace('_', ' ')}: {n}")

        st.markdown("#### Masked file (safe to share)")
        show_sheets(read_preview(res["masked"], ext, header_row))

        st.markdown("#### Downloads")
        base = f"{stem}.masked{ext}"
        d1, d2, d3 = st.columns(3)
        d1.download_button("Masked file", res["masked"], base, MIME[ext])
        d2.download_button("Mapping (encrypted)", res["map"], base + ".map.enc", "application/octet-stream")
        d3.download_button("Key", res["key"], base + ".key", "application/octet-stream")
        st.warning("Keep the **mapping** and the **key** private. Never share them with the masked file.")

    # ---- de-mask
    st.divider()
    st.markdown("#### 2) De-mask a file")
    modes = ["Upload masked file + mapping + key"]
    if res:
        modes.insert(0, "Use the file I just masked")
    mode = st.radio("Source", modes, horizontal=True)

    if mode.startswith("Use"):
        masked_b, map_b, key_b = res["masked"], res["map"], res["key"]
        de_ext, de_hr = res["ext"], res["header_row"]
    else:
        u1, u2, u3 = st.columns(3)
        mf = u1.file_uploader("Masked file", type=["csv", "xlsx"], key="up_masked")
        mp = u2.file_uploader("Mapping (.enc)", type=["enc"], key="up_map")
        kf = u3.file_uploader("Key (.key)", type=["key"], key="up_key")
        if not (mf and mp and kf):
            st.info("Upload all three files.")
            return
        masked_b, map_b, key_b = mf.getvalue(), mp.getvalue(), kf.getvalue()
        de_ext, de_hr = Path(mf.name).suffix.lower(), header_row

    if st.button("De-mask file"):
        with st.spinner("Restoring..."):
            try:
                out = unmask_bytes(masked_b, map_b, key_b, de_ext, de_hr)
                out["sheets"] = read_preview(out["restored"], de_ext, de_hr)
                out["ext"] = de_ext
                out["from_last"] = mode.startswith("Use")
                st.session_state.file_restored = out
            except Exception as e:
                st.session_state.pop("file_restored", None)
                st.error(f"De-masking failed: {e}")

    out = st.session_state.get("file_restored")
    if out:
        restored = out["stats"].get(("restored",), 0)
        st.success(f"Restored {restored} token(s).")
        if out["stats"].get(("unknown_token",), 0):
            st.warning(f"{out['stats'][('unknown_token',)]} token(s) were not in the mapping (left as-is).")
        show_sheets(out["sheets"])
        if out["from_last"] and res:
            if same_content(res["original"], out["sheets"]):
                st.success("Round-trip check passed: the restored file is identical to the original.")
            else:
                st.error("Round-trip check FAILED: the restored file differs from the original.")
        st.download_button("Restored file", out["restored"], f"{stem}.restored{out['ext']}", MIME[out["ext"]])


# ================================================================== UI: about tab
def tab_about():
    st.markdown("""
### How the pipeline works
```
Input -> 1) Detect -> 2) Policy check -> 3) Mask -> 4) Validate -> safe output -> (AI) -> De-mask
```
1. **Detect**: regex + validators (NID date check, Luhn, IBAN mod-97), name dictionary, optional NER models.
2. **Policy check**: in text mode a detected *secret* (password, API key...) blocks the whole text.
3. **Mask**: every sensitive value becomes a random token such as `[[PHONE_A1B2C3D4]]`.
4. **Validate**: fail-closed re-check. Any problem blocks the output.
5. **De-mask**: tokens in the AI reply are replaced by the original values using a mapping that never leaves your machine.

### Files
* Column-aware: headers like `الاسم`, `الرقم القومي`, `العنوان`, `كلمة المرور` mask the whole cell.
* Content-aware: other columns are scanned cell by cell.
* The mapping is saved **encrypted** (Fernet) in a separate file, with its own key file.
* In file mode, password columns are tokenized (reversible) so they can be restored.
""")


# ================================================================== main
def main():
    st.set_page_config(page_title="GOVSHIELD", page_icon="🛡️", layout="wide")
    st.session_state.setdefault("mapping", {})
    st.session_state.setdefault("input_text", SAMPLES[0])
    st.session_state.setdefault("ai_reply", "")

    with st.sidebar:
        st.title("🛡️ GOVSHIELD")
        st.caption("Local privacy gateway - masking & de-masking")
        st.markdown("**Engine settings**")
        use_ner = st.checkbox("Use NER models (slower, better names)", value=False,
                              help="Loads CAMeLBERT / dslim BERT from HuggingFace on first use.")
        strict = st.checkbox("Strict names", value=True,
                             help="Mask any known first name even when it appears alone.")
        packs = st.multiselect("Packs", ["core", "finance"], default=["core", "finance"])
        st.checkbox("Detect addresses (text mode)", value=True, key="with_address")
        apply_engine_settings(use_ner, strict, packs)
        st.divider()
        st.button("Clear session", on_click=_clear_session)

    t1, t2, t3 = st.tabs(["📝 Text", "📁 CSV / Excel", "ℹ️ About"])
    with t1:
        tab_text()
    with t2:
        tab_file()
    with t3:
        tab_about()


if __name__ == "__main__":
    main()
