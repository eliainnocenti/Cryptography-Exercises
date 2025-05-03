# long secret message

# This is a long message encrypted a line at the time...
# (Remember, flag format is CRYPTO25{<uuid4>})

import binascii
import re
import sys
from typing import List, Optional, Tuple

def read_ciphertext(path: str) -> List[bytes]:
    """
    Read hex-encoded ciphertext lines from a file and return them as a list of byte strings.
    """
    try:
        with open(path, "r") as f:
            lines = [line.strip() for line in f if line.strip()] # Read and strip non-empty lines
    except FileNotFoundError:
        print(f"[ERROR] Ciphertext file not found: {path}")
        sys.exit(1)

    ciphertexts = []
    for lineno, line in enumerate(lines, 1):
        try:
            # Convert each hex-encoded line to bytes
            ciphertexts.append(binascii.unhexlify(line))
        except (binascii.Error, ValueError) as e:
            print(f"[ERROR] Invalid hex on line {lineno}: {e}")
            sys.exit(1)
    return ciphertexts

def read_plaintext(path: str) -> List[bytes]:
    """
    Read plaintext lines from a file and return them as a list of byte strings.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [line.rstrip("\n").encode("utf-8") for line in f] # Read and encode each line
    except FileNotFoundError:
        print(f"[ERROR] Plaintext file not found: {path}")
        sys.exit(1)

def derive_keystream_line(ct_line: bytes, pt_line: bytes) -> bytes:
    """
    Derive the keystream by XOR-ing a ciphertext line with its corresponding plaintext line.
    """
    length = min(len(ct_line), len(pt_line)) # Use the shorter length to avoid index errors
    return bytes(ct_line[i] ^ pt_line[i] for i in range(length)) # XOR each byte

def decrypt_with_keystream(ciphertexts: List[bytes], keystream: bytes) -> Optional[bytes]:
    """
    Attempt to decrypt all ciphertext lines using a repeating keystream.
    """
    full = bytearray()  # Initialize a bytearray to store the full decrypted plaintext
    for ct in ciphertexts:
        plain_line = bytearray()
        for j, c in enumerate(ct):
            ks_byte = keystream[j % len(keystream)] # Use the keystream in a repeating manner
            plain_line.append(c ^ ks_byte) # XOR each byte of the ciphertext with the keystream
        try:
            # Validate that the decrypted line is valid UTF-8
            decoded = plain_line.decode("utf-8")
        except UnicodeDecodeError:
            return None # Return None if any line fails to decode
        full.extend(plain_line) # Append the decrypted line to the full plaintext
    return bytes(full)

def extract_flag(decrypted: bytes) -> Optional[str]:
    """
    Search the decrypted plaintext for a UUID4 and return the flag string if found.
    """
    prefix = b"CRYPTO25{" # The expected flag prefix
    start = decrypted.find(prefix) # Find the start of the flag
    if start == -1:
        return None

    # UUID4 regex: 8-4-4-4-12 with version 4 and variant 8,9,a,b
    uuid4_pattern = re.compile(
        rb"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
    )
    matches = list(uuid4_pattern.finditer(decrypted))
    if not matches:
        return None

    # Take the last match as most plausible
    uuid_bytes = matches[-1].group(0)
    return f"CRYPTO25{{{uuid_bytes.decode('utf-8')}}}"

def main():
    """
    Main function to solve the challenge by deriving the keystream,
    decrypting the ciphertext, and extracting the flag.
    """
    # File paths
    enc_path = "hacker-manifesto.enc" # Path to the encrypted file
    txt_path = "hacker-manifesto.txt" # Path to the plaintext file

    print("Reading files...")
    ciphertexts = read_ciphertext(enc_path) # Read the ciphertext lines
    plaintexts = read_plaintext(txt_path)   # Read the plaintext lines

    if len(ciphertexts) != len(plaintexts):
        print("[WARNING] Number of ciphertext lines and plaintext lines differ.")

    print("Deriving keystream from known plaintext lines...")
    for idx, (ct_line, pt_line) in enumerate(zip(ciphertexts, plaintexts)):
        keystream = derive_keystream_line(ct_line, pt_line) # Derive the keystream for the current line
        decrypted = decrypt_with_keystream(ciphertexts, keystream) # Attempt to decrypt all ciphertexts
        if decrypted is None:
            continue # Skip if decryption fails

        print(f"[+] Valid keystream found using line {idx+1} (length {len(keystream)})")
        # Print the decrypted manifest
        try:
            print("\nDecrypted manifest:")
            print(decrypted.decode("utf-8"))
        except Exception:
            pass

        # Attempt to extract the flag
        flag = extract_flag(decrypted)
        if flag:
            print(f"\n[+] FLAG FOUND: {flag}")
            sys.exit(0)
        else:
            print("[!] Flag pattern not found in decrypted text.")
            sys.exit(1)

    print("[ERROR] No valid keystream produced a UTF-8 plaintext.")
    sys.exit(1)

if __name__ == "__main__":
    main()
