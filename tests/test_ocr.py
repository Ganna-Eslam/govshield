"""OCR protection tests (synthetic data only). Run: python tests/test_ocr.py"""
import os
import random
import sys
import tempfile
import time

os.environ.setdefault("GOVSHIELD_NER_MODEL", "none")
os.environ.setdefault("GOVSHIELD_NER_MODEL_EN", "none")
sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "privacy-engine", "files"))

from PIL import Image, ImageDraw, ImageFilter, ImageFont  # noqa: E402
import ocr_engine  # noqa: E402
from ocr_engine import OcrBlocked, protect_file, _ocr_words, _build_text  # noqa: E402
from file_masker import mask_file, unmask_file  # noqa: E402

FONT_PATHS = [os.environ.get("GOVSHIELD_TEST_FONT", ""),
              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
              "C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/tahoma.ttf"]
FONT = next((p for p in FONT_PATHS if p and os.path.exists(p)), None)


def ar(text):
    """Prepare Arabic for drawing. With raqm Pillow shapes and reorders by itself."""
    from PIL import features
    if features.check("raqm"):
        return text
    import arabic_reshaper
    from bidi.algorithm import get_display
    return get_display(arabic_reshaper.reshape(text))


# (line to draw, [secrets that must disappear], [plain words that should survive])
AR_LINES = [
    ("بيانات الموظف", [], ["بيانات"]),
    ("الاسم: أحمد محمد", ["أحمد", "محمد"], []),
    ("الرقم القومي 29012345678901", ["29012345678901"], []),
    ("الموبايل 01012345678", ["01012345678"], []),
    ("البريد ahmed@gmail.com", ["ahmed@gmail.com"], []),
    ("يرجى مراجعة الطلب قبل نهاية الأسبوع", [], ["مراجعة"]),
]
EN_LINES = [
    ("Employee record review", [], ["Employee", "review"]),
    ("Phone: 01112345678", ["01112345678"], []),
    ("Email: khaled.ali@example.com", ["khaled.ali@example.com"], []),
    ("National ID 29812345678912", ["29812345678912"], []),
    ("Please send the report by Friday", [], ["report", "Friday"]),
]


def draw_doc(lines, arabic, size=34, w=1200):
    font = ImageFont.truetype(FONT, size)
    img = Image.new("RGB", (w, 90 + len(lines) * (size + 40)), "white")
    d = ImageDraw.Draw(img)
    y = 50
    for text, _, _ in lines:
        shown = ar(text) if arabic else text
        if arabic:
            bbox = d.textbbox((0, 0), shown, font=font)
            d.text((w - 60 - (bbox[2] - bbox[0]), y), shown, font=font, fill="black")
        else:
            d.text((60, y), shown, font=font, fill="black")
        y += size + 40
    return img


def variants(img):
    yield "clean", img
    yield "blur", img.filter(ImageFilter.GaussianBlur(1.2))
    yield "rotated", img.rotate(2, expand=True, fillcolor="white")
    yield "small", img.resize((img.width // 2, img.height // 2), Image.LANCZOS)
    rnd = random.Random(7)
    noisy = img.copy()
    px = noisy.load()
    for _ in range(img.width * img.height // 60):
        x, y = rnd.randrange(img.width), rnd.randrange(img.height)
        v = rnd.choice((0, 255))
        px[x, y] = (v, v, v)
    yield "noise", noisy


def read_text(path):
    if path.lower().endswith(".pdf"):
        import pymupdf
        doc = pymupdf.open(path)
        imgs = []
        for p in doc:
            pix = p.get_pixmap(dpi=250, alpha=False)
            imgs.append(Image.frombytes("RGB", (pix.width, pix.height), pix.samples))
    else:
        imgs = [Image.open(path).convert("RGB")]
    return " ".join(_build_text(_ocr_words(i, "gray_psm3")) for i in imgs)


def check(lines, arabic, tmp, tag):
    secrets = [s for _, ss, _ in lines for s in ss]
    plain = [w for _, _, ws in lines for w in ws]
    base = draw_doc(lines, arabic)
    results = []
    for name, img in variants(base):
        src = os.path.join(tmp, f"{tag}_{name}.png")
        dst = os.path.join(tmp, f"{tag}_{name}.masked.png")
        img.save(src)
        t0 = time.time()
        try:
            r = protect_file(src, dst)
        except OcrBlocked as e:
            # blocking is an acceptable fail-closed result, but no output may exist
            assert not os.path.exists(dst), "output left behind after block"
            results.append((name, "BLOCKED", str(e), time.time() - t0))
            continue
        dt = time.time() - t0
        txt = read_text(dst)
        leaks = [s for s in secrets if s in txt or (s.isascii() and s in txt.replace(" ", ""))]
        assert not leaks, f"LEAK in {tag}/{name}: {len(leaks)} value(s) readable"
        kept = sum(1 for w in plain if w in txt)
        results.append((name, "OK", f"kept {kept}/{len(plain)} plain words, {sum(r['stats'].values())} redactions", dt))
    for name, status, info, dt in results:
        print(f"  {tag:3} {name:8} {status:8} {dt:5.1f}s  {info}")
    ok = [r for r in results if r[1] == "OK"]
    assert any(r[0] == "clean" and r[1] == "OK" for r in results), f"{tag}: clean image must not be blocked"
    return results


def test_exif_and_format(tmp):
    img = draw_doc(EN_LINES, False)
    src, dst = os.path.join(tmp, "e.jpg"), os.path.join(tmp, "e.masked.jpg")
    exif = Image.Exif()
    exif[0x010F] = "SecretCamera"
    img.save(src, "JPEG", quality=92, exif=exif.tobytes())
    assert Image.open(src).getexif(), "test setup: EXIF missing"
    protect_file(src, dst)
    assert not Image.open(dst).getexif(), "EXIF survived"
    print("  EXIF removed, JPEG output OK")


def test_blocks(tmp):
    # corrupt
    bad = os.path.join(tmp, "bad.png")
    open(bad, "wb").write(b"not an image")
    # blank (no text)
    blank = os.path.join(tmp, "blank.png")
    Image.new("RGB", (800, 600), "white").save(blank)
    # unsupported type
    odd = os.path.join(tmp, "x.gif")
    Image.new("RGB", (50, 50), "white").save(odd)
    # too large
    huge = os.path.join(tmp, "huge.png")
    Image.new("RGB", (600, 600), "white").save(huge)
    cases = [("corrupt", bad), ("blank", blank), ("gif", odd)]
    for name, p in cases:
        dst = p + ".out.png"
        try:
            protect_file(p, dst)
        except OcrBlocked:
            assert not os.path.exists(dst)
            continue
        raise AssertionError(f"{name} should be blocked")
    old = ocr_engine.MAX_PIXELS
    ocr_engine.MAX_PIXELS = 1000
    try:
        protect_file(huge, huge + ".out.png")
        raise AssertionError("oversize should be blocked")
    except OcrBlocked:
        pass
    finally:
        ocr_engine.MAX_PIXELS = old
    # OCR engine unavailable -> block
    old_langs = ocr_engine.LANGS
    ocr_engine.LANGS = "zzz"
    try:
        protect_file(os.path.join(tmp, "e.jpg"), os.path.join(tmp, "z.jpg"))
        raise AssertionError("missing language data should block")
    except OcrBlocked:
        pass
    finally:
        ocr_engine.LANGS = old_langs
    print("  corrupt / blank / unsupported / oversize / engine-missing all blocked, no output left")


def make_pdf(tmp, pages, name, encrypt=False):
    import pymupdf
    doc = pymupdf.open()
    for lines, arabic in pages:
        img = draw_doc(lines, arabic)
        p = os.path.join(tmp, "pg.png")
        img.save(p)
        page = doc.new_page(width=595, height=842)
        page.insert_image(page.rect, filename=p)
    path = os.path.join(tmp, name)
    if encrypt:
        doc.save(path, encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw="x", owner_pw="y")
    else:
        doc.save(path)
    return path


def test_pdf(tmp):
    src = make_pdf(tmp, [(AR_LINES, True), (EN_LINES, False)], "scan.pdf")
    dst = os.path.join(tmp, "scan.masked.pdf")
    t0 = time.time()
    r = protect_file(src, dst)
    dt = time.time() - t0
    import pymupdf
    doc = pymupdf.open(dst)
    assert doc.page_count == 2
    assert not any(p.get_text().strip() for p in doc), "output PDF must not carry a text layer"
    txt = read_text(dst).replace(" ", "")
    for s in ("29012345678901", "01012345678", "ahmed@gmail.com", "01112345678",
              "khaled.ali@example.com", "29812345678912"):
        assert s not in txt, "LEAK in PDF"
    print(f"  2-page scanned PDF OK in {dt:.1f}s, {sum(r['stats'].values())} redactions")
    enc = make_pdf(tmp, [(EN_LINES, False)], "enc.pdf", encrypt=True)
    try:
        protect_file(enc, os.path.join(tmp, "enc.masked.pdf"))
        raise AssertionError("encrypted PDF should be blocked")
    except OcrBlocked:
        pass
    open(os.path.join(tmp, "junk.pdf"), "wb").write(b"%PDF-1.4 garbage")
    try:
        protect_file(os.path.join(tmp, "junk.pdf"), os.path.join(tmp, "junk.masked.pdf"))
        raise AssertionError("corrupt PDF should be blocked")
    except OcrBlocked:
        pass
    print("  encrypted and corrupt PDFs blocked")


def test_api(tmp):
    src = os.path.join(tmp, "api.png")
    draw_doc(EN_LINES, False).save(src)
    r = mask_file(src, os.path.join(tmp, "api.masked.png"))
    assert r["map_file"] is None and r["reversible"] is False
    assert not os.path.exists(os.path.join(tmp, "api.masked.png.map.enc"))
    try:
        unmask_file(os.path.join(tmp, "api.masked.png"), os.path.join(tmp, "api.restored.png"))
        raise AssertionError("unmask of image must refuse")
    except ValueError:
        pass
    print("  mask_file routes images, no mapping file, unmask refused")


if __name__ == "__main__":
    ok, reason = ocr_engine.ocr_ready()
    if not ok:
        sys.exit(f"OCR not ready: {reason}. Install Tesseract with ara+eng data "
                 "or set GOVSHIELD_TESSERACT_CMD / GOVSHIELD_TESSDATA.")
    if not FONT:
        sys.exit("No Arabic-capable font found; set GOVSHIELD_TEST_FONT to a .ttf path.")
    with tempfile.TemporaryDirectory() as tmp:
        print("Arabic image, quality variants:")
        check(AR_LINES, True, tmp, "ar")
        print("English image, quality variants:")
        check(EN_LINES, False, tmp, "en")
        test_exif_and_format(tmp)
        test_blocks(tmp)
        test_pdf(tmp)
        test_api(tmp)
    print("ALL PASSED")
