import datetime
import re
from dataclasses import dataclass


@dataclass
class Detection:
    type: str
    start: int
    end: int
    value: str
    confidence: float = 1.0
    source: str = "regex"


class Recognizer:
    entity = ""
    pack = "core"

    def find(self, text: str, norm: str) -> list:
        raise NotImplementedError


class RegexRecognizer(Recognizer):
    def __init__(self, entity, pattern, pack="core", validator=None,
                 confidence=0.9, invalid_confidence=0.7, require_valid=False, flags=0):
        self.entity = entity
        self.pattern = re.compile(pattern, flags)
        self.pack = pack
        self.validator = validator
        self.confidence = confidence
        self.invalid_confidence = invalid_confidence
        self.require_valid = require_valid

    def find(self, text, norm):
        out = []
        for m in self.pattern.finditer(norm):
            conf = self.confidence
            if self.validator:
                if self.validator(m.group()):
                    conf = 0.99
                elif self.require_valid:
                    continue
                else:
                    conf = self.invalid_confidence
            out.append(Detection(self.entity, m.start(), m.end(),
                                 text[m.start():m.end()], conf))
        return out


# ---------- Validators ----------
def digits(s):
    return re.sub(r"\D", "", s)


def luhn_ok(s):
    d = [int(c) for c in digits(s)]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def egypt_nid_ok(s):
    d = digits(s)
    if len(d) != 14:
        return False
    century = {"2": 1900, "3": 2000}.get(d[0])
    if not century:
        return False
    try:
        datetime.date(century + int(d[1:3]), int(d[3:5]), int(d[5:7]))
    except ValueError:
        return False
    return True


def iban_ok(s):
    s = re.sub(r"\s", "", s).upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        number = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1