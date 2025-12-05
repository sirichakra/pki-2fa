import json
import requests


def request_seed(student_id: str, github_repo_url: str, api_url: str) -> None:
    """
    Request encrypted seed from instructor API

    Steps:
    1. Read student public key from PEM file
       - Open and read the public key file
       - Keep the PEM format with BEGIN/END markers

    2. Prepare HTTP POST request payload
       - Create JSON with student_id, github_repo_url, public_key
       - Most HTTP libraries handle newlines in JSON automatically

    3. Send POST request to instructor API
       - Use your language's HTTP client
       - Set Content-Type: application/json
       - Include timeout handling

    4. Parse JSON response
       - Extract 'encrypted_seed' field
       - Handle error responses appropriately

    5. Save encrypted seed to file
       - Write to encrypted_seed.txt as plain text
    """
    # 1. Read student public key
    with open("student_public.pem", "r") as f:
        public_key_text = f.read()

    # 2. Prepare JSON payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_text,
    }

    # 3. Send POST request
    response = requests.post(
        api_url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    response.raise_for_status()

    # 4. Parse JSON
    data = response.json()
    encrypted_seed = data["encrypted_seed"]

    # 5. Save to encrypted_seed.txt
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)



if __name__ == "__main__":
    STUDENT_ID = "23A91A05K1"  
    GITHUB_REPO_URL = "https://github.com/sirichakra/pki-2fa" 
    API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"  

    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)
    print("Saved encrypted_seed.txt")
