# Back to the future

# You may have to make different guesses if you want to go in the past, 
# but if you understood the code, they would not be too much!
# http://130.192.5.212:6522

# HINT: have a look at the Python requests library, don't be scared by the sessions.

# HINT2: pay 80 points... if you think you have the solution but are encountering some problems when executing the exploit...

"""
This script automates:
 1. Logging in as admin to obtain a ChaCha20 keystream.
 2. Forging an encrypted cookie with a manipulated expiration timestamp.
 3. Iterating guesses until the server returns the flag.
"""

import time
import sys
import requests
from typing import Tuple, Optional
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Target URL of the challenge
URL = "http://130.192.5.212:6522"

def to_bytes(n: int) -> bytes:
    """
    Convert an integer to big-endian bytes without leading zeros.
    """
    return long_to_bytes(n)

def to_int(b: bytes) -> int:
    """
    Convert bytes to an integer.
    """
    return bytes_to_long(b)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte sequences of equal length.
    """
    return bytes(x ^ y for x, y in zip(a, b))

def initial_login(session: requests.Session) -> Tuple[bytes, bytes]:
    """
    Perform initial login as admin to retrieve nonce and derive keystream.
    Args:
        session (requests.Session): The HTTP session to use for requests.
    Returns:
        Tuple[bytes, bytes]: The nonce and the derived keystream.
    """
    # Send a login request with admin privileges
    params = {"username": "admin", "admin": "1"}
    resp = session.get(f"{URL}/login", params=params)
    resp.raise_for_status()
    data = resp.json()

    # Extract nonce and ciphertext from the server's response
    nonce = to_bytes(data.get("nonce"))
    ciphertext = to_bytes(data.get("cookie"))

    # Construct the expected plaintext for the admin cookie
    expires = int(time.time()) + 30 * 24 * 3600  # 30 days from now
    plaintext = f"username=admin&expires={expires}&admin=1"
    plaintext_bytes = plaintext.encode()

    # Derive the keystream by XOR-ing the plaintext and ciphertext
    if len(ciphertext) != len(plaintext_bytes):
        print("[ERROR] Unexpected ciphertext length vs plaintext length.")
        sys.exit(1)
    keystream = xor_bytes(ciphertext, plaintext_bytes)

    print(f"[+] Obtained keystream (length {len(keystream)}) using expires={expires}")
    return nonce, keystream

def forge_cookie_and_request(
    session: requests.Session,
    nonce: bytes,
    keystream: bytes,
    expire_guess: int
) -> Optional[str]:
    """
    Forge a cookie with a guessed expiration timestamp and request /flag.
    Args:
        session (requests.Session): The HTTP session to use for requests.
        nonce (bytes): The nonce used for encryption.
        keystream (bytes): The derived keystream.
        expire_guess (int): The guessed expiration timestamp.
    Returns:
        Optional[str]: The server's response text if the flag is found, otherwise None.
    """
    # Construct the cookie string with the guessed expiration timestamp
    cookie_str = f"username=admin&expires={expire_guess}&admin=1"
    cookie_bytes = cookie_str.encode()

    # XOR the cookie string with the keystream to produce the forged ciphertext
    if len(cookie_bytes) != len(keystream):
        print("[ERROR] Cookie length and keystream length mismatch.")
        return None
    forged_cipher = xor_bytes(cookie_bytes, keystream)

    # Send the forged cookie to the server
    params = {"nonce": str(to_int(nonce)), "cookie": str(to_int(forged_cipher))}
    resp = session.get(f"{URL}/flag", params=params)
    
    # Return the server's response text for inspection
    return resp.text

def brute_force_expiry(
    session: requests.Session,
    nonce: bytes,
    keystream: bytes,
    min_days: int = 10,
    max_days: int = 259,
    offset_days: int = 295
):
    """
    Brute-force the admin_expire_date difference by trying expire dates.
    Args:
        session (requests.Session): The HTTP session to use for requests.
        nonce (bytes): The nonce used for encryption.
        keystream (bytes): The derived keystream.
        min_days (int): Minimum number of days to guess for admin_expire_date.
        max_days (int): Maximum number of days to guess for admin_expire_date.
        offset_days (int): Offset to add to the guessed admin_expire_date.
    """
    now = int(time.time())  # Current timestamp
    for days_ago in range(min_days, max_days + 1):
        # Guess the admin_expire_date as now - days_ago
        guessed_admin_expire = now - days_ago * 24 * 3600
        # Set the expiration timestamp as guessed_admin_expire + offset_days
        expire_guess = guessed_admin_expire + offset_days * 24 * 3600
        text = forge_cookie_and_request(session, nonce, keystream, expire_guess)
        if text is None:
            continue
        print(f"[Attempt {days_ago}] expires={expire_guess} → {text}")
        if "flag" in text.lower():
            print("\n[+] Flag retrieved successfully!")
            print(text)
            return
    print("[!] Failed to retrieve flag after brute-forcing.")

def main():
    """
    Main function to automate the process of logging in, deriving the keystream,
    and brute-forcing the expiration timestamp to retrieve the flag.
    """
    # Create a persistent HTTP session to preserve Flask session data
    session = requests.Session()

    # Step 1: Login and derive the keystream
    nonce, keystream = initial_login(session)

    # Step 2: Brute-force the expiration timestamp and fetch the flag
    brute_force_expiry(session, nonce, keystream)

if __name__ == "__main__":
    main()
