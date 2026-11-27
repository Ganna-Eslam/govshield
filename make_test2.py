from openpyxl import Workbook

wb = Workbook()
ws = wb.active
ws.append(["اسم المنتج", "كود المواطن", "المرتب", "بيانات التواصل", "الرقم السري للدخول"])
ws.append(["لابتوب", "29012345678901", 15000, "منى سيد", "Pass1234"])
ws.append(["ماوس", "29512345678901", 200, "كريم علي", "Qw3rty99"])
wb.save("samples/data.xlsx")
print("Created samples/data.xlsx")