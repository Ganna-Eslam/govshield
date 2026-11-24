import json
import os
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8")
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "privacy-engine", "detection"))
from detect import detect  # noqa: E402

DATA = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE, "tests", "dataset", "data.jsonl")


def overlap(a_s, a_e, b_s, b_e):
    return max(0, min(a_e, b_e) - max(a_s, b_s))


gold_total, gold_hit = Counter(), Counter()
det_total, det_ok = Counter(), Counter()
misses, false_pos = [], []
leaky = n = 0

with open(DATA, encoding="utf-8") as f:
    for line in f:
        ex = json.loads(line)
        text, gold = ex["text"], ex["entities"]
        dets = detect(text)
        n += 1
        leaked = False

        for g in gold:
            gold_total[g["type"]] += 1
            glen = g["end"] - g["start"]
            covered = sum(overlap(g["start"], g["end"], d.start, d.end) for d in dets)
            if covered >= 0.8 * glen:
                gold_hit[g["type"]] += 1
            else:
                leaked = True
                misses.append((g["type"], text[g["start"]:g["end"]], text))

        for d in dets:
            det_total[d.type] += 1
            if any(g["type"] == d.type and overlap(g["start"], g["end"], d.start, d.end) > 0 for g in gold):
                det_ok[d.type] += 1
            else:
                false_pos.append((d.type, d.value, text))

        leaky += leaked

types = sorted(set(gold_total) | set(det_total))
print(f"{'TYPE':8} {'GOLD':>5} {'RECALL':>8} {'DETECTED':>9} {'PRECISION':>10} {'F1':>6}")
for t in types:
    rec = gold_hit[t] / gold_total[t] if gold_total[t] else 0
    pre = det_ok[t] / det_total[t] if det_total[t] else 0
    f1 = 2 * rec * pre / (rec + pre) if (rec + pre) else 0
    print(f"{t:8} {gold_total[t]:5} {rec:8.2%} {det_total[t]:9} {pre:10.2%} {f1:6.2f}")

print(f"\nExamples with at least one leak: {leaky}/{n}")

print("\n--- MISSED (leaks), first 15 ---")
for t, v, text in misses[:15]:
    print(f"[{t}] {v!r}   in: {text}")

print("\n--- FALSE POSITIVES, first 10 ---")
for t, v, text in false_pos[:10]:
    print(f"[{t}] {v!r}   in: {text}")