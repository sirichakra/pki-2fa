import base64
import time

import pyotp

from decrypt_seed import load_student_private_key, decrypt_seed


def _hex_to_base32(hex_seed: str) -> str:
    """
    Helper: convert 64-character hex seed to base32 string.

    Implementation:
    1. Convert hex string to raw bytes
    2. Encode bytes using base32
    3. Decode to normal string (UTF-8)
    """
    seed_bytes = bytes.fromhex(hex_seed)          # step 1
    base32_seed = base64.b32encode(seed_bytes)    # step 2
    return base32_seed.decode("utf-8")            # step 3


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed.

    Args:
        hex_seed: 64-character hex string

    Returns:
        6-digit TOTP code as string

    Implementation (matches your Step 6):

    1. Convert hex seed to bytes          → in _hex_to_base32()
    2. Convert bytes to base32 encoding   → in _hex_to_base32()
    3. Create TOTP object using base32 seed
       - SHA-1 (default)
       - 30 second period
       - 6 digits
    4. Generate current TOTP code
    5. Return the code
    """
    base32_seed = _hex_to_base32(hex_seed)

    # SHA-1, 30s interval, 6 digits are the defaults for pyotp.TOTP
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # Current 6-digit code as string, e.g. "123456"
    code = totp.now()
    return code


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance.

    Args:
        hex_seed: 64-character hex string
        code:     6-digit code to verify
        valid_window: Number of periods before/after to accept
                      (default 1 = ±30 seconds)

    Returns:
        True if code is valid, False otherwise

    Implementation (matches your Verification section):

    1. Convert hex seed to base32 (same as generation)
    2. Create TOTP object with base32 seed
    3. Verify code with time window tolerance
       - Use valid_window parameter (default 1 = ±30s)
       - Library checks current period ± valid_window periods
    4. Return verification result
    """
    base32_seed = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # valid_window=1 → current time slice ±1 slice (±30s)
    is_valid = totp.verify(code, valid_window=valid_window)
    return is_valid


# ---------------------------------------------------------
# Optional test runner for Step 6
# You can run:  py totp_utils.py
# It will:
#   1. Decrypt your encrypted_seed.txt using decrypt_seed.py
#   2. Generate a TOTP code
#   3. Verify that code (should be True)
#   4. Verify a wrong code (should be False)
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
