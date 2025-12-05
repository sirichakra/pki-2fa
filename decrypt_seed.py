import base64
import string

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_student_private_key(path: str = "student_private.pem"):
    """
    Helper function to load your RSA private key from a PEM file.

    This is not in the problem statement, but it makes it easy to
    get the 'private_key' object needed by decrypt_seed().
    """
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP.

    Args:
        encrypted_seed_b64: Base64-encoded ciphertext string
        private_key: RSA private key object

    Returns:
        Decrypted hex seed (64-character string)

    Implementation (matches assignment Step 5):

    1. Base64 decode the encrypted seed string
    2. RSA/OAEP decrypt with SHA-256
       - Padding: OAEP
       - MGF: MGF1(SHA-256)
       - Hash: SHA-256
       - Label: None
    3. Decode bytes to UTF-8 string
    4. Validate: must be 64-character hex string
       - Check length is 64
       - Check all characters are in '0123456789abcdefABCDEF'
    5. Return hex seed
    """

    # 1. Base64 decode the encrypted seed string
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt with SHA-256
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decode bytes to UTF-8 string
    hex_seed = plaintext_bytes.decode("utf-8")

    # 4. Validate: must be 64-character hex string
    if len(hex_seed) != 64:
        raise ValueError("Decrypted seed must be 64 characters long")

    # Check that every character is a valid hex digit
    if not all(ch in string.hexdigits for ch in hex_seed):
        raise ValueError("Decrypted seed must contain only hex characters")

    # 5. Return hex seed
    return hex_seed


# ---------------------------------------------------------
# Optional: small test runner for Step 5
# This lets you run:  py decrypt_seed.py
# ---------------------------------------------------------
if __name__ == "__main__":
    # 1. Read the base64 encrypted seed from file
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()

    # 2. Load your private key
    private_key = load_student_private_key("student_private.pem")

    # 3. Decrypt
    hex_seed = decrypt_seed(encrypted_seed_b64, private_key)

    # 4. Print result (for checking)
    print("Decrypted seed:", hex_seed)
    print("Length:", len(hex_seed))
