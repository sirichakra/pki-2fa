import subprocess
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---- Step 1: Get the latest commit hash ----
def get_latest_commit_hash():
    result = subprocess.run(["git", "log", "-1", "--format=%H"], capture_output=True, text=True)
    return result.stdout.strip()


# ---- Step 2: Load private key (student_private.pem) ----
def load_private_key():
    with open("student_private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ---- Step 3: Sign using RSA-PSS with SHA-256 ----
def sign_commit(commit_hash, private_key):
    signature = private_key.sign(
        commit_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


# ---- Step 4: Encrypt the signature using instructor_public.pem ----
def encrypt_signature(signature):
    with open("instructor_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    encrypted = public_key.encrypt(
        signature,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


# ---- Step 5: Base64 encode final output ----
def encode_output(data):
    return base64.b64encode(data).decode()


# ---- Main Execution ----
if __name__ == "__main__":
    commit_hash = get_latest_commit_hash()
    print(f"\n🔹 Commit Hash:\n{commit_hash}\n")

    private_key = load_private_key()
    signature = sign_commit(commit_hash, private_key)
    encrypted_signature = encrypt_signature(signature)

    b64_output = encode_output(encrypted_signature)

    print(f"🔹 Encrypted Signature (Base64):\n{b64_output}\n")

    print("✅ Copy BOTH values for submission.")
