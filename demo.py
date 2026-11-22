import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
base = os.path.dirname(os.path.abspath(__file__))
for sub in ("detection", "masking", "validation"):
    sys.path.insert(0, os.path.join(base, "privacy-engine", sub))

from detect import detect
from mask import mask, restore
from validate import validate


def protect(text):
    try:
        dets = detect(text)
        safe, mapping = mask(text, dets)
        ok, reason = validate(safe, mapping)
        if not ok:
            return {"status": "blocked", "reason": reason}  # Fail-closed
        return {"status": "protected", "safe_text": safe, "mapping": mapping, "count": len(dets)}
    except Exception as e:
        return {"status": "blocked", "reason": f"error: {e}"}  # Fail-closed


if __name__ == "__main__":
    tests = [
        "حلل شكوى أحمد محمد، رقمه القومي 29012345678901، وتليفونه 01012345678",
        "كلمني على +201112345678 أو ahmed@gmail.com",
        "الرقم القومي ٢٩٠١٢٣٤٥٦٧٨٩٠١ والموبايل ٠١٠١٢٣٤٥٦٧٨",
        "التليفون 010 1234 5678",   # متوقع يفوت: ده اختبار ليكي
        "نص عادي مفيهوش حاجة",
                "موبايلي 010-1234-5678",
        "الرقم القومي 2901 2345 6789 01",
        "كلمني +20 111 234 5678"
    ]
    for t in tests:
        r = protect(t)
        print("IN :", t)
        print("OUT:", r.get("safe_text", r))
        if r["status"] == "protected":
            print("BACK:", restore(r["safe_text"], r["mapping"]))
        print("-" * 60)