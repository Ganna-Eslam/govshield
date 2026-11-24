import json
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(BASE, "testset_source.txt")
OUT = os.path.join(BASE, "dataset", "testset.jsonl")
TAG = re.compile(r"\{(PERSON|NID|PHONE|EMAIL|CARD|IBAN|SECRET)\|([^}]*)\}")

rows = []
with open(SRC, encoding="utf-8") as f:
    for ln, line in enumerate(f, 1):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        text, ents, pos = "", [], 0
        for m in TAG.finditer(line):
            text += line[pos:m.start()]
            val = m.group(2)
            ents.append({"type": m.group(1), "start": len(text), "end": len(text) + len(val)})
            text += val
            pos = m.end()
        text += line[pos:]
        if re.search(r"\{\w+\|", text):
            print(f"WARNING line {ln}: unparsed tag, check the format -> {line}")
        rows.append({"text": text, "entities": ents})

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", encoding="utf-8") as f:
    for r in rows:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")
print(f"wrote {len(rows)} examples to {OUT}")