import os
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from decrypt_seed import load_student_private_key, decrypt_seed
from totp_utils import generate_totp_code, verify_totp_code

# FastAPI application
app = FastAPI()

# Where the decrypted seed must be stored (inside container / Docker volume)
DATA_PATH = "/data/seed.txt"


# ---------- Request models ----------

class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


# ---------- Helper to read stored seed ----------

def read_hex_seed() -> str | None:
    """
    Read hex seed from /data/seed.txt.
    Returns None if file does not exist.
    """
    if not os.path.exists(DATA_PATH):
        return None

    with open(DATA_PATH, "r") as f:
        return f.read().strip()


# ---------- Endpoint 1: POST /decrypt-seed ----------

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptRequest):
    """
    Request:
        { "encrypted_seed": "BASE64_STRING..." }

    On success (200):
        { "status": "ok" }

    On failure (500):
        { "error": "Decryption failed" }
    """
    try:
        # 1. Load student private key
        private_key = load_student_private_key("student_private.pem")

        # 2. Decrypt the base64 string to get 64-char hex seed
        hex_seed = decrypt_seed(body.encrypted_seed, private_key)

        # 3. Ensure /data directory exists
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)

        # 4. Store hex seed at /data/seed.txt
        with open(DATA_PATH, "w") as f:
            f.write(hex_seed)

        # 5. Return success response
        return {"status": "ok"}

    except Exception:
        # Any error → HTTP 500 with specific message
        return JSONResponse(
            status_code=500,
            content={"error": "Decryption failed"},
        )


# ---------- Endpoint 2: GET /generate-2fa ----------

@app.get("/generate-2fa")
def generate_2fa():
    """
    On success (200):
        { "code": "123456", "valid_for": 30 }

    On error if seed missing (500):
        { "error": "Seed not decrypted yet" }
    """
    hex_seed = read_hex_seed()
    if hex_seed is None:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    # Generate current TOTP code from hex seed
    code = generate_totp_code(hex_seed)

    # Remaining seconds in current 30-second window
    valid_for = 30 - (int(time.time()) % 30)

    return {"code": code, "valid_for": valid_for}


# ---------- Endpoint 3: POST /verify-2fa ----------

@app.post("/verify-2fa")
def verify_2fa(body: VerifyRequest | None = None):
    """
    Request:
        { "code": "123456" }

    Responses:
        200 OK:
            { "valid": true }  or  { "valid": false }

        400 Bad Request (missing code):
            { "error": "Missing code" }

        500 Internal Server Error (seed missing):
            { "error": "Seed not decrypted yet" }
    """
    # 1. Validate that code is provided
    if body is None or not body.code:
        return JSONResponse(
            status_code=400,
            content={"error": "Missing code"},
        )

    # 2. Read stored seed
    hex_seed = read_hex_seed()
    if hex_seed is None:
        return JSONResponse(
            status_code=500,
            content={"error": "Seed not decrypted yet"},
        )

    # 3. Verify TOTP code with ±1 period tolerance
    is_valid = verify_totp_code(hex_seed, body.code, valid_window=1)

    # 4. Return result
    return {"valid": is_valid}
