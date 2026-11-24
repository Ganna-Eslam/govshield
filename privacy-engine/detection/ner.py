import os
import re

from base import Detection, Recognizer

# "none" = يوقف الموديل ده
AR_MODEL = os.environ.get("GOVSHIELD_NER_MODEL", "CAMeL-Lab/bert-base-arabic-camelbert-da-ner")
EN_MODEL = os.environ.get("GOVSHIELD_NER_MODEL_EN", "dslim/bert-base-NER")
MIN_SCORE = float(os.environ.get("GOVSHIELD_NER_MIN_SCORE", "0.0"))
CHUNK = 400  # حروف. الموديل بياخد 512 token بالكتير

# الموديل الإنجليزي بيشتغل بس لما النص فيه كلمات لاتينية
LATIN_WORD = re.compile(r"[A-Za-z]{3,}")

_pipes = {}


def _get_pipe(model_name):
    if model_name not in _pipes:
        from transformers import pipeline
        _pipes[model_name] = pipeline("ner", model=model_name, aggregation_strategy="simple")
    return _pipes[model_name]


def _chunks(text, size=CHUNK):
    start, n = 0, len(text)
    while start < n:
        end = min(start + size, n)
        if end < n:
            cut = text.rfind(" ", start, end)
            if cut > start:
                end = cut
        yield start, end
        start = end


class NerRecognizer(Recognizer):
    entity = "PERSON"
    pack = "core"

    def __init__(self, model_name, source, only_if=None):
        self.model_name = model_name
        self.source = source
        self.only_if = only_if

    def find(self, text, norm):
        if self.model_name.lower() == "none":
            return []
        if self.only_if and not self.only_if.search(text):
            return []
        nlp = _get_pipe(self.model_name)  # لو فشل التحميل بيرمي Exception فالـpipeline تعمل Block
        out = []
        for s, e in _chunks(text):
            piece = text[s:e]
            if not piece.strip():
                continue
            for ent in nlp(piece):
                if not ent["entity_group"].upper().startswith("PER"):
                    continue
                if ent["score"] < MIN_SCORE:
                    continue
                a, b = s + ent["start"], s + ent["end"]
                out.append(Detection("PERSON", a, b, text[a:b], float(ent["score"]), self.source))
        return out