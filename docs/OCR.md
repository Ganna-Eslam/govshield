# OCR for images and scanned PDFs

Status: implemented on branch `feature/ocr`. It was Out of Scope for the MVP (BRD 4.2), so
adding it needs a change-control entry (SRS 14.4).

## What it does
- Supported: PNG, JPG/JPEG, BMP, TIFF (single frame) and PDF (every page is rendered as an image).
- Tesseract reads the text (ara+eng, two passes with different preprocessing).
- The same detection used for text/CSV/XLSX runs on the recognised text.
- Matching words are painted over with black boxes. Words read with low confidence are painted too.
- The output is rebuilt from pixels (EXIF and metadata are dropped). A PDF output has no text layer
  and no metadata.
- The protected file is read by OCR again. If anything sensitive can still be read, the file is blocked.

## Blocked (no output file is written)
Corrupt or unreadable file, unsupported type, multi-frame image, encrypted PDF, too many pages,
image too large, OCR engine or language data missing, OCR timeout, no readable text,
text too unclear to verify, sensitive data still readable after protection.

## Behaviour to know
- Irreversible: there is no mapping or key file and `unmask` refuses images.
- A PDF with a real text layer is also rasterised and OCR'd, so its text layer is not kept.
- An image with no text at all is blocked (cannot be verified). Set `GOVSHIELD_OCR_ALLOW_NO_TEXT=1`
  to allow it, only if the team decides so.

## Settings (environment variables)
`GOVSHIELD_TESSERACT_CMD`, `GOVSHIELD_TESSDATA`, `GOVSHIELD_OCR_LANGS` (default `ara+eng`),
`GOVSHIELD_OCR_MIN_CONF` (50), `GOVSHIELD_OCR_MIN_PAGE_CONF` (40), `GOVSHIELD_OCR_MAX_PIXELS`,
`GOVSHIELD_OCR_MAX_PAGES` (30), `GOVSHIELD_OCR_TIMEOUT` (90 s per OCR call), `GOVSHIELD_OCR_PDF_DPI` (250).

## Setup on Windows
1. Install Tesseract (UB Mannheim build) and tick the Arabic language data, or copy `ara.traineddata`
   into its `tessdata` folder.
2. If it is not on PATH, set `GOVSHIELD_TESSERACT_CMD` to `tesseract.exe`.
3. `pip install -r requirements.txt`, then `python tests/test_ocr.py`.

## Known limits (state these in the report)
- Only text that Tesseract reads can be protected. Handwriting, very low resolution, stylised fonts,
  text on busy backgrounds and heavy noise may be missed or over-covered.
- Digits can be misread (for example O and 0), so a number may not match the ID/phone pattern.
- Arabic OCR accuracy is lower than English. Measure it on your own scans before claiming coverage.
- Images with a name that is not in the name dictionary are protected only when the NER model is on.
- The tests use synthetic images drawn by code, not real scans.
