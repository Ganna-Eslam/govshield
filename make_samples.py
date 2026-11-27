import csv
import os
from openpyxl import Workbook

os.makedirs("samples", exist_ok=True)

header = ["الاسم", "الرقم القومي", "رقم الموبايل", "العنوان", "كلمة المرور", "ملاحظات", "المرتب"]
rows = [
    ["أحمد محمد", "29012345678901", "01012345678", "12 شارع التحرير، الدقي، الجيزة",
     "Hunter2xyz", "كلمني على ahmed@gmail.com", "5000"],
    ["منى سيد", "29512345678901", "010 1234 5679", "برج النيل كورنيش المعادي",
     "P@ss-123", "العميل ساكن في شارع الهرم", "7000"],
    ["كريم علي", "29812345678901", "01234567890", "5 ش الجمهورية المنصورة",
     "abc12345", "مفيش ملاحظات", "6000"],
]

# CSV (utf-8-sig so Excel shows Arabic correctly)
with open("samples/people.csv", "w", encoding="utf-8-sig", newline="") as f:
    csv.writer(f).writerows([header] + rows)

# Excel
wb = Workbook()
ws = wb.active
ws.title = "Employees"
ws.append(header)
for r in rows:
    ws.append(r)
wb.save("samples/people.xlsx")
print("Created samples/people.csv and samples/people.xlsx")