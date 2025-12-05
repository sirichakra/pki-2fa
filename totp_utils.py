import base64
import time

import pyotp

from decrypt_seed import load_student_private_key, decrypt_seed


def _hex_to_base32(hex_seed: str) -> str:
    """
    Helper: convert 64-character hex seed to base32 string.
    """
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes)
    return base32_seed.decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed.

    Uses:
    - SHA-1
    - 30-second period
    - 6 digits
    """
    base32_seed = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance (± valid_window periods).

    Instead of relying on the library's verify(), we explicitly check
    the code for the current period and ± valid_window periods.
    """
    base32_seed = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    now = int(time.time())

    # Check current period and ±valid_window periods
    for offset in range(-valid_window, valid_window + 1):
        t = now + offset * 30
        if totp.at(t) == code:
            return True

    return False


# ---------------------------------------------------------
# Optional test runner
# ---------------------------------------------------------
if __name__ == "__main__":
    # 1. Read encrypted seed from file
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()

    # 2. Load private key and decrypt to get hex seed
    private_key = load_student_private_key("student_private.pem")
    hex_seed = decrypt_seed(encrypted_seed_b64, private_key)
    print("Hex seed (first 8 chars):", hex_seed[:8], "...")

    # 3. Generate current TOTP code
    code = generate_totp_code(hex_seed)
    print("Current TOTP code:", code)

    # 4. Verify the correct code (should be True)
    is_valid = verify_totp_code(hex_seed, code, valid_window=1)
    print("Verifying correct code →", is_valid)

    # 5. Verify an incorrect code (should be False)
    is_valid_wrong = verify_totp_code(hex_seed, "000000", valid_window=1)
    print("Verifying wrong code '000000' →", is_valid_wrong)
