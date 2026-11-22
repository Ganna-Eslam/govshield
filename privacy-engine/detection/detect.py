import os
import re
from dataclasses import dataclass

# تحويل الأرقام العربية للإنجليزية (نفس الطول، فالـpositions تفضل صح)
AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
# تطبيع الحروف (نفس الطول). مقصود إن ى متتغيرش عشان "على" متبقاش "علي"
AR_LETTERS = str.maketrans("أإآة", "اايه")

SEP = r"[\s\-]?"

PATTERNS = {
    "NID": re.compile(r"(?<!\d)[23](?:" + SEP + r"\d){13}(?!\d)"),
    "PHONE": re.compile(r"(?<!\d)(?:\+?20" + SEP + r"|0)1[0125](?:" + SEP + r"\d){8}(?!\d)"),
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
}

# قوايم مبدئية. وسعيها بنفسك من داتا حقيقية
FIRST_NAMES_RAW = """
محمد احمد محمود مصطفى علي عمر يوسف ابراهيم اسماعيل خالد حسن حسين طارق عمرو كريم ياسر
هشام ايمن سامح وائل اسلام عبد سعيد صلاح رضا ماجد مجدي رامي شريف امير ادم زياد مروان
هيثم سيد فتحي جمال نبيل عادل ماهر ممدوح طه حمدي حازم مصطفي
فاطمة مريم منى سارة نور هبة ايمان اية هدى دعاء رنا رحمة سلمى نادية امل داليا اميرة
شيماء نهى ريهام جنة ياسمين مي منة ندى هند سمر سلوى عايدة سعاد نجلاء
"""
TITLES_RAW = """
السيد السيدة الاستاذ الاستاذة استاذ استاذة المهندس المهندسة مهندس مهندسة
الدكتور الدكتورة دكتور دكتورة الحاج الحاجة المواطن المواطنة الموظف الموظفة
المريض المريضة العميل العميلة اسمه اسمها
"""


@dataclass
class Detection:
    type: str
    start: int
    end: int
    value: str


def normalize(text: str) -> str:
    return text.translate(AR_DIGITS)


def norm_ar(s: str) -> str:
    return s.translate(AR_LETTERS)


FIRST_NAMES = {norm_ar(w) for w in FIRST_NAMES_RAW.split()}
TITLES = {norm_ar(w) for w in TITLES_RAW.split()}
WORD = re.compile(r"[\u0621-\u064A]+")  # حروف عربية فقط (من غير الفاصلة العربية)

# Strict: أي اسم أول من القائمة يتحمي حتى لو لوحده (Fail-Closed)
STRICT_NAMES = os.environ.get("GOVSHIELD_STRICT_NAMES", "1") == "1"


def _adjacent(text, a_end, b_start):
    return text[a_end:b_start].strip() == ""


def detect_names(text: str) -> list[Detection]:
    words = []
    for m in WORD.finditer(text):
        s, e, w = m.start(), m.end(), norm_ar(m.group())
        # واو العطف اللازقة: "وأحمد" -> "أحمد"
        if w not in FIRST_NAMES and w.startswith("و") and w[1:] in FIRST_NAMES:
            s, w = s + 1, w[1:]
        words.append((s, e, w))

    results = []
    i = 0
    while i < len(words):
        if words[i][2] in FIRST_NAMES:
            j = i
            while (j + 1 < len(words) and j - i < 3
                   and words[j + 1][2] in FIRST_NAMES
                   and _adjacent(text, words[j][1], words[j + 1][0])):
                j += 1
            titled = (i > 0 and words[i - 1][2] in TITLES
                      and _adjacent(text, words[i - 1][1], words[i][0]))
            if (j - i + 1) >= 2 or titled or STRICT_NAMES:
                s, e = words[i][0], words[j][1]
                results.append(Detection("PERSON", s, e, text[s:e]))
            i = j + 1
        else:
            i += 1
    return results


def detect(text: str) -> list[Detection]:
    norm = normalize(text)
    found = []
    for t, pattern in PATTERNS.items():
        for m in pattern.finditer(norm):
            found.append(Detection(t, m.start(), m.end(), text[m.start():m.end()]))
    found.extend(detect_names(text))

    # شيل التداخل
    found.sort(key=lambda d: (d.start, -(d.end - d.start)))
    result, last_end = [], -1
    for d in found:
        if d.start >= last_end:
            result.append(d)
            last_end = d.end
    return result