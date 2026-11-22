import os
import secrets
import sys

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "privacy-engine"))
from pipeline import protect, restore  # noqa: E402

# Token للتحقق بين الـExtension والـService
TOKEN = os.environ.get("GOVSHIELD_TOKEN") or secrets.token_urlsafe(24)
if not os.environ.get("GOVSHIELD_TOKEN"):
    print("GOVSHIELD token:", TOKEN)

# الـMapping بيتخزن في الذاكرة بس ومبيرجعش للـExtension أبدًا
SESSIONS: dict[str, dict] = {}

app = FastAPI(title="GOVSHIELD Local Service")


class ProtectRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)
    text: str = Field(max_length=20000)


class RestoreRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)
    text: str = Field(max_length=50000)


def check_token(token: str | None):
    if not token or not secrets.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/api/v1/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/protect/text")
def protect_text(req: ProtectRequest, x_govshield_token: str | None = Header(default=None)):
    check_token(x_govshield_token)
    result = protect(req.text)
    if result["status"] != "protected":
        return {"status": "blocked", "outbound_allowed": False, "reason": result["reason"]}
    SESSIONS.setdefault(req.session_id, {}).update(result["mapping"])
    return {
        "status": "protected",
        "safe_text": result["safe_text"],
        "detections_count": result["count"],
        "outbound_allowed": True,
    }


@app.post("/api/v1/restore/response")
def restore_response(req: RestoreRequest, x_govshield_token: str | None = Header(default=None)):
    check_token(x_govshield_token)
    mapping = SESSIONS.get(req.session_id, {})
    return {"text": restore(req.text, mapping)}