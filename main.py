import time
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# =========================
# Configuration
# =========================
RATE_LIMIT = 43            # per minute
BURST_LIMIT = 11           # bucket capacity
REFILL_RATE = RATE_LIMIT / 60  # tokens per second

# In-memory store (Use Redis in production)
rate_limit_store = {}

# =========================
# Logging Setup
# =========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# =========================
# Request Model
# =========================
class SecurityRequest(BaseModel):
    userId: str
    input: str
    category: str


# =========================
# Utility Functions
# =========================
def get_client_key(request: Request, user_id: str):
    ip = request.client.host
    return f"{user_id}-{ip}"


def check_rate_limit(key: str):
    now = time.time()

    if key not in rate_limit_store:
        rate_limit_store[key] = {
            "tokens": BURST_LIMIT,
            "last_refill": now
        }

    bucket = rate_limit_store[key]

    # Refill tokens
    elapsed = now - bucket["last_refill"]
    refill = elapsed * REFILL_RATE

    bucket["tokens"] = min(BURST_LIMIT, bucket["tokens"] + refill)
    bucket["last_refill"] = now

    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return True, 0

    retry_after = (1 - bucket["tokens"]) / REFILL_RATE
    return False, int(retry_after) + 1


def log_security_event(event_type: str, details: dict):
    logging.info({
        "event_type": event_type,
        "details": details
    })


# =========================
# API Endpoint
# =========================
@app.post("/security/validate")
async def validate_security(data: SecurityRequest, request: Request):

    try:
        # Basic validation
        if not data.userId or not data.input or not data.category:
            return JSONResponse(
                status_code=400,
                content={
                    "blocked": True,
                    "reason": "Invalid request format",
                    "sanitizedOutput": None,
                    "confidence": 0.98
                }
            )

        key = get_client_key(request, data.userId)

        allowed, retry_after = check_rate_limit(key)

        if not allowed:
            log_security_event(
                "RATE_LIMIT_BLOCK",
                {"userId": data.userId, "retry_after": retry_after}
            )

            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "blocked": True,
                    "reason": "Too many requests. Please retry later.",
                    "sanitizedOutput": None,
                    "retryAfter": retry_after,
                    "confidence": 0.99
                }
            )

        # Passed security checks
        return {
            "blocked": False,
            "reason": "Input passed all security checks",
            "sanitizedOutput": data.input,
            "confidence": 0.95
        }

    except Exception:
        log_security_event("SYSTEM_ERROR", {})
        return JSONResponse(
            status_code=500,
            content={
                "blocked": True,
                "reason": "Internal validation error",
                "sanitizedOutput": None,
                "confidence": 0.90
            }
        )
