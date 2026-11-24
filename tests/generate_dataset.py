import datetime
import json
import os
import random
import re
import string

rng = random.Random(42)  # ثابت عشان النتايج تتكرر
AR_DIG = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")


def digits(n):
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


def rand_str(n, alphabet=string.ascii_letters + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


# ---------------- Generators ----------------
def gen_nid():
    century = rng.choice(["2", "3"])
    year = rng.randint(1950, 1999) if century == "2" else rng.randint(2000, 2010)
    d = datetime.date(year, rng.randint(1, 12), rng.randint(1, 28))
    raw = century + d.strftime("%y%m%d") + f"{rng.randint(1, 35):02d}" + digits(4) + digits(1)
    style = rng.choice(["plain", "plain", "spaced", "arabic"])
    if style == "spaced":
        return " ".join([raw[0:4], raw[4:8], raw[8:12], raw[12:14]])
    if style == "arabic":
        return raw.translate(AR_DIG)
    return raw


def gen_phone():
    p = rng.choice(["010", "011", "012", "015"])
    rest = digits(8)
    style = rng.choice(["plain", "plain", "spaced", "dashed", "intl", "arabic"])
    if style == "spaced":
        return f"{p} {rest[:4]} {rest[4:]}"
    if style == "dashed":
        return f"{p}-{rest[:4]}-{rest[4:]}"
    if style == "intl":
        return f"+20{p[1:]}{rest}"
    if style == "arabic":
        return (p + rest).translate(AR_DIG)
    return p + rest


def gen_email():
    user = rng.choice(["ahmed", "mona", "omar.hassan", "sara_ali", "khaled", "nour"]) + digits(rng.randint(0, 3))
    return f"{user}@{rng.choice(['gmail.com', 'yahoo.com', 'company.com.eg', 'outlook.com'])}"


def luhn_check_digit(partial):
    total = 0
    for i, ch in enumerate(reversed(partial)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - total % 10) % 10)


def gen_card():
    partial = rng.choice(["4", "5"]) + digits(14)
    raw = partial + luhn_check_digit(partial)
    groups = [raw[i:i + 4] for i in range(0, 16, 4)]
    return rng.choice([raw, " ".join(groups), "-".join(groups)])


def gen_iban():
    bban = digits(25)
    rearranged = bban + "EG" + "00"
    number = "".join(str(int(c, 36)) for c in rearranged)
    iban = f"EG{98 - int(number) % 97:02d}{bban}"
    if rng.random() < 0.5:
        iban = " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))
    return iban


def gen_secret():
    kind = rng.choice(["pw", "pw_ar", "aws", "sk"])
    if kind == "pw":
        return "password: " + rand_str(10)
    if kind == "pw_ar":
        return "كلمة السر: " + rand_str(9)
    if kind == "aws":
        return "AKIA" + rand_str(16, string.ascii_uppercase + string.digits)
    return "sk-" + rand_str(32)


MALE = ["محمد", "أحمد", "محمود", "مصطفى", "عمر", "يوسف", "إبراهيم", "خالد", "كريم",
        "عبدالرحمن", "ياسين", "حمزة", "مازن", "تامر", "بهاء", "سيف", "أسامة", "وليد"]
FEMALE = ["منى", "سارة", "نور", "هبة", "إيمان", "آية", "بسمة", "ميرنا", "ريم",
          "جيهان", "نيرة", "دينا", "لمياء", "شروق"]
FATHERS = ["محمد", "علي", "حسن", "إبراهيم", "السيد", "عبدالله", "فتحي", "مصطفى",
           "عبدالعزيز", "سليمان"]


def gen_person():
    parts = [rng.choice(MALE + FEMALE), rng.choice(FATHERS)]
    if rng.random() < 0.3:
        parts.append(rng.choice(FATHERS))
    return " ".join(parts)


def gen_person_en():
    return rng.choice(["Ahmed Mohamed", "Mona Ali", "Omar Hassan", "Sara Ibrahim", "Khaled Mostafa"])


GEN = {"PERSON": gen_person, "PERSON_EN": gen_person_en, "NID": gen_nid, "PHONE": gen_phone,
       "EMAIL": gen_email, "CARD": gen_card, "IBAN": gen_iban, "SECRET": gen_secret}

# ---------------- Templates ----------------
TEMPLATES = [
    "حلل شكوى {PERSON}، رقمه القومي {NID}، وتليفونه {PHONE}",
    "المواطن {PERSON} بيشتكي من تأخر الطلب، كلمه على {PHONE}",
    "ابعت الرد على {EMAIL} وخلي {PERSON} يراجعه",
    "الموظفة {PERSON} رقمها {PHONE} وإيميلها {EMAIL}",
    "الرقم القومي للمريض {NID}",
    "تم التحويل على البطاقة {CARD} النهاردة",
    "حسابي البنكي {IBAN} ومحتاج أراجع الحركات",
    "اسمه {PERSON} وساكن في القاهرة",
    "{PERSON} و{PERSON} حضروا الاجتماع",
    "الإعداد اللي عندي هو {SECRET} وعايز أدخل",
    "كلمني على {PHONE} لو في أي حاجة",
    "بيانات العميل: {PERSON} - {NID} - {EMAIL}",
    "Please summarize the complaint from {PERSON_EN}, phone {PHONE}",
    "Send the invoice to {EMAIL} for {PERSON_EN}",
    "My card number is {CARD} and my IBAN is {IBAN}",
    "Here is my config: {SECRET}",
]

NEGATIVES = [
    "الاجتماع الساعة 5 يوم الخميس في القاعة الكبيرة",
    "المبلغ المطلوب 5000 جنيه والباقي 12000",
    "رقم الطلب 1234567890 بتاع الشحنة",
    "الطقس النهاردة حلو ونور الشمس جميلة",
    "اكتبلي ملخص عن تاريخ مصر القديمة",
    "الاجتماع يوم 20 يناير 2024 الساعة 10",
    "رقم الشحنة 123456789012 وصل المخزن",
    "The meeting is at 5 pm in room 12",
    "Order number 123456789012 shipped yesterday",
    "Please write a summary of the quarterly report",
    "نص عادي مفيهوش حاجة",
    "عايز أعرف الفرق بين الخطة الشهرية والسنوية",
]

SLOT = re.compile(r"\{(\w+)\}")


def render(template):
    out, ents, pos = "", [], 0
    for m in SLOT.finditer(template):
        out += template[pos:m.start()]
        val = GEN[m.group(1)]()
        etype = "PERSON" if m.group(1) == "PERSON_EN" else m.group(1)
        ents.append({"type": etype, "start": len(out), "end": len(out) + len(val)})
        out += val
        pos = m.end()
    out += template[pos:]
    return out, ents


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(base, "dataset"), exist_ok=True)
    path = os.path.join(base, "dataset", "data.jsonl")
    rows = []
    for _ in range(300):
        text, ents = render(rng.choice(TEMPLATES))
        rows.append({"text": text, "entities": ents})
    for _ in range(60):
        rows.append({"text": rng.choice(NEGATIVES), "entities": []})
    rng.shuffle(rows)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} examples to {path}")