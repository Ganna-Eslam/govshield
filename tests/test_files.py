"""Round-trip tests for file masking. Run: python tests/test_files.py"""
import csv
import os
import sys
import tempfile

os.environ.setdefault("GOVSHIELD_NER_MODEL", "none")
os.environ.setdefault("GOVSHIELD_NER_MODEL_EN", "none")
sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "privacy-engine", "files"))
from file_masker import mask_file, unmask_file  # noqa: E402

HEADER = ["الاسم", "الرقم القومي", "رقم الموبايل", "العنوان", "كلمة المرور", "ملاحظات", "المرتب"]
ROWS = [
    ["أحمد محمد", "29012345678901", "01012345678", "12 شارع التحرير، الدقي، الجيزة",
     "Hunter2xyz", "كلمني على ahmed@gmail.com", "5000"],
    ["منى سيد", "٢٩٠١٢٣٤٥٦٧٨٩٠١", "010 1234 5678", "برج النيل كورنيش المعادي",
     "P@ss-123", "العميل ساكن في شارع الهرم وبيدفع كاش", "7000"],
    ["أحمد محمد", "29012345678901", "", "", "Hunter2xyz", "password: abc123xyz", "5000"],
]
SECRETS = ["أحمد", "منى", "29012345678901", "01012345678", "Hunter2xyz", "P@ss-123",
           "ahmed@gmail.com", "التحرير", "abc123xyz", "الهرم", "المعادي"]


def check_no_leak(text):
    leaks = [s for s in SECRETS if s in text]
    assert not leaks, f"LEAK: {leaks}"


def test_csv(tmp):
    src, masked, restored = (os.path.join(tmp, n) for n in ("in.csv", "in.masked.csv", "in.restored.csv"))
    with open(src, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows([HEADER] + ROWS)
    r = mask_file(src, masked)
    check_no_leak(open(masked, encoding="utf-8-sig").read())
    check_no_leak(open(r["map_file"], "rb").read().decode("latin1"))  # mapping is encrypted
    unmask_file(masked, restored)
    a = list(csv.reader(open(src, encoding="utf-8-sig")))
    b = list(csv.reader(open(restored, encoding="utf-8-sig")))
    assert a == b, "CSV round-trip mismatch"
    print("CSV  OK  | tokens:", r["unique_tokens"])


def test_xlsx(tmp):
    from openpyxl import Workbook, load_workbook
    src, masked, restored = (os.path.join(tmp, n) for n in ("in.xlsx", "in.masked.xlsx", "in.restored.xlsx"))
    wb = Workbook()
    ws = wb.active
    ws.append(HEADER)
    for r in ROWS:
        ws.append(r)
    ws.append(["سيد فتحي", 29012345678902, 1012345679, "", "x", "", 100])  # numeric NID / phone
    ws["G6"] = "=SUM(G2:G5)"
    wb.create_sheet("Sheet2").append(["Name", "Email"])
    wb["Sheet2"].append(["Khaled Ali", "k.ali@example.com"])
    wb.save(src)

    r = mask_file(src, masked)
    m = load_workbook(masked)
    dump = " ".join(str(c.value) for w in m.worksheets for row in w.iter_rows() for c in row)
    check_no_leak(dump)
    assert "29012345678902" not in dump and "k.ali@example.com" not in dump
    unmask_file(masked, restored)
    o, n = load_workbook(src), load_workbook(restored)
    for w in o.worksheets:
        for row in w.iter_rows():
            for c in row:
                got = n[w.title][c.coordinate].value
                assert str(got) == str(c.value), f"{w.title}!{c.coordinate}: {c.value!r} != {got!r}"
    print("XLSX OK  | tokens:", r["unique_tokens"])


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        test_csv(tmp)
        test_xlsx(tmp)
    print("ALL PASSED")
