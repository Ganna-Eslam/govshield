import json
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "privacy-engine", "detection"))
from detect import detect  # noqa: E402
from transformers import pipeline  # noqa: E402

DATA = os.path.join(BASE, "tests", "dataset", "data.jsonl")
MODELS = [
    "CAMeL-Lab/bert-base-arabic-camelbert-da-ner",
    "CAMeL-Lab/bert-base-arabic-camelbert-mix-ner",
    "CAMeL-Lab/bert-base-arabic-camelbert-msa-ner",
]
AR = re.compile(r"[\u0600-\u06FF]")


def load():
    keep = []
    with open(DATA, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            gold = [g for g in r["entities"] if g["type"] == "PERSON"]
            if all(AR.search(r["text"][g["start"]:g["end"]]) for g in gold):
                keep.append((r["text"], gold))
    return keep


def merge(spans):
    out = []
    for s, e in sorted(spans):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def covered(g, spans):
    total = 0
    for s, e in merge(spans):
        total += max(0, min(e, g["end"]) - max(s, g["start"]))
    return total / (g["end"] - g["start"])


def evaluate(label, predict, data):
    hit = total = fp = pred = 0
    missed = []
    for text, gold in data:
        spans = predict(text)
        for g in gold:
            total += 1
            if covered(g, spans) >= 0.8:
                hit += 1
            else:
                missed.append(text[g["start"]:g["end"]])
        for s, e in spans:
            pred += 1
            if not any(min(e, g["end"]) > max(s, g["start"]) for g in gold):
                fp += 1
    recall = hit / total if total else 0
    prec = (pred - fp) / pred if pred else 0
    print(f"{label:34} recall {recall:7.2%}   precision {prec:7.2%}   missed {total - hit}/{total}")
    return missed


def rules(text):
    return [(d.start, d.end) for d in detect(text) if d.type == "PERSON"]


data = load()
print(f"{len(data)} examples\n")
evaluate("rules only (current)", rules, data)

for name in MODELS:
    short = name.split("camelbert-")[1]
    nlp = pipeline("ner", model=name, aggregation_strategy="simple")

    def model_spans(text, nlp=nlp):
        return [(e["start"], e["end"]) for e in nlp(text)
                if e["entity_group"].upper().startswith("PER")]

    evaluate(f"{short} alone", model_spans, data)
    missed = evaluate(f"{short} + rules", lambda t: model_spans(t) + rules(t), data)
    print("   sample misses:", missed[:6])