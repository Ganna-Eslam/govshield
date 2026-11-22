import os
import re

from base import (Detection, Recognizer, RegexRecognizer,
                  egypt_nid_ok, luhn_ok, iban_ok)

# تحويل الأرقام العربية للإنجليزية (نفس الطول، فالـpositions تفضل صح)
AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
# تطبيع الحروف (نفس الطول). مقصود إن ى متتغيرش عشان "على" متبقاش "علي"
AR_LETTERS = str.maketrans("أإآة", "اايه")

SEP = r"[\s\-]?"

# الـPacks المفعلة. تتغير بمتغير بيئة: GOVSHIELD_PACKS=core,finance,health
ENABLED_PACKS = set(os.environ.get("GOVSHIELD_PACKS", "core,finance").split(","))

# Strict: أي اسم أول من القائمة يتحمي حتى لو لوحده (Fail-Closed)
STRICT_NAMES = os.environ.get("GOVSHIELD_STRICT_NAMES", "1") == "1"

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


def normalize(text: str) -> str:
    return text.translate(AR_DIGITS)


def norm_ar(s: str) -> str:
    return s.translate(AR_LETTERS)


FIRST_NAMES = {norm_ar(w) for w in FIRST_NAMES_RAW.split()}
TITLES = {norm_ar(w) for w in TITLES_RAW.split()}
WORD = re.compile(r"[\u0621-\u064A]+")


def _adjacent(text, a_end, b_start):
    return text[a_end:b_start].strip() == ""


class NameRecognizer(Recognizer):
    entity = "PERSON"
    pack = "core"

    def find(self, text, norm):
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
                multi = (j - i + 1) >= 2
                if multi or titled or STRICT_NAMES:
                    s, e = words[i][0], words[j][1]
                    conf = 0.85 if (multi or titled) else 0.6
                    results.append(Detection("PERSON", s, e, text[s:e], conf, "dictionary"))
                i = j + 1
            else:
                i += 1
        return results


# ---------------- Registry ----------------
REGISTRY: list[Recognizer] = [
    # core
    RegexRecognizer("NID", r"(?<!\d)[23](?:" + SEP + r"\d){13}(?!\d)",
                    pack="core", validator=egypt_nid_ok, confidence=0.9, invalid_confidence=0.7),
    RegexRecognizer("PHONE", r"(?<!\d)(?:\+?20" + SEP + r"|0)1[0125](?:" + SEP + r"\d){8}(?!\d)",
                    pack="core", confidence=0.95),
    RegexRecognizer("EMAIL", r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", pack="core", confidence=0.99),
    NameRecognizer(),
    RegexRecognizer("SECRET", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", pack="core", confidence=0.99),
    RegexRecognizer("SECRET", r"\bAKIA[0-9A-Z]{16}\b", pack="core", confidence=0.99),
    RegexRecognizer("SECRET", r"\bsk-[A-Za-z0-9_\-]{20,}", pack="core", confidence=0.95),
    RegexRecognizer("SECRET",
                    r"(?:password|passwd|pwd|كلمة\s*(?:السر|المرور))\s*[:=]\s*\S+",
                    pack="core", confidence=0.9, flags=re.IGNORECASE),
    # finance
    RegexRecognizer("CARD", r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)",
                    pack="finance", validator=luhn_ok, require_valid=True),
    RegexRecognizer("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b",
                    pack="finance", validator=iban_ok, require_valid=True),
    # health / hr / gov: هنضيفهم بعد ما نحدد الأنواع
]


def detect(text: str) -> list[Detection]:
    norm = normalize(text)
    found = []
    for r in REGISTRY:
        if r.pack in ENABLED_PACKS:
            found.extend(r.find(text, norm))

    # شيل التداخل: الأطول أولاً، وعند التساوي الأعلى ثقة
    found.sort(key=lambda d: (d.start, -(d.end - d.start), -d.confidence))
    result, last_end = [], -1
    for d in found:
        if d.start >= last_end:
            result.append(d)
            last_end = d.end
    return result