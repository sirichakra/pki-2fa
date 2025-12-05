#!/usr/bin/env python3
"""
Cron script to log 2FA codes every minute.
"""

import os
import base64
import datetime
import pyotp

DATA_PATH = "/data/seed.txt"


def hex_to_base32(hex_seed: str) -> str:
    """Convert 64-char hex seed to base32 string."""
    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode("utf-8")


def main():
    try:
        # 1. Read hex seed from persistent storage
        if not os.path.exists(DATA_PATH):
            print("Error: /data/seed.txt not found")
            return

        with open(DATA_PATH, "r") as f:
            hex_seed = f.read().strip()

        if not hex_seed:
            print("Error: seed file is empty")
            return

        # 2. Generate current TOTP code (same settings as API)
        base32_seed = hex_to_base32(hex_seed)
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
        code = totp.now()

        # 3. Get current UTC timestamp
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # 4. Output formatted line
        #    Format: "YYYY-MM-DD HH:MM:SS - 2FA Code: XXXXXX"
        print(f"{ts} - 2FA Code: {code}")

    except Exception as e:
        # Handle any unexpected error gracefully
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
