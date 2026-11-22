import re
from dataclasses import dataclass

# تحويل الأرقام العربية للإنجليزية (نفس الطول، فالـpositions تفضل صح)
AR_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")

SEP = r"[\s\-]?"

PATTERNS = {
    "NID": re.compile(r"(?<!\d)[23](?:" + SEP + r"\d){13}(?!\d)"),
    "PHONE": re.compile(r"(?<!\d)(?:\+?20" + SEP + r"|0)1[0125](?:" + SEP + r"\d){8}(?!\d)"),
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
}


@dataclass
class Detection:
    type: str
    start: int
    end: int
    value: str


def normalize(text: str) -> str:
    return text.translate(AR_DIGITS)


def detect(text: str) -> list[Detection]:
    norm = normalize(text)
    found = []
    for t, pattern in PATTERNS.items():
        for m in pattern.finditer(norm):
            found.append(Detection(t, m.start(), m.end(), text[m.start():m.end()]))

    # شيل التداخل (مثلاً إيميل فيه رقم موبايل)
    found.sort(key=lambda d: (d.start, -(d.end - d.start)))
    result, last_end = [], -1
    for d in found:
        if d.start >= last_end:
            result.append(d)
            last_end = d.end
    return result