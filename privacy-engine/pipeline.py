import os
import sys

_base = os.path.dirname(os.path.abspath(__file__))
for sub in ("detection", "masking", "validation"):
    sys.path.insert(0, os.path.join(_base, sub))

from detect import detect
from mask import mask, restore
from validate import validate


def protect(text):
    try:
        dets = detect(text)

        # الأسرار التقنية بتتمنع ومبتتحولش لـToken
        if any(d.type == "SECRET" for d in dets):
            return {"status": "blocked", "reason": "secret detected"}

        safe, mapping = mask(text, dets)
        ok, reason = validate(safe, mapping)
        if not ok:
            return {"status": "blocked", "reason": reason}  # Fail-closed
        return {"status": "protected", "safe_text": safe, "mapping": mapping, "count": len(dets)}
    except Exception as e:
        return {"status": "blocked", "reason": f"error: {e}"}  # Fail-closed