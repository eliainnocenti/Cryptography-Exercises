# long file

# this file has not been encrypted one line at the time... maybe...

# === Attack Overview ===
# - Attack Type: Keystream Reuse
# - Implementation Attack
# - Weakness: Use of a short, repeating XOR keystream
# - Brief Attack Description:
#     The ciphertext is encrypted with a 1000-byte repeating XOR keystream.
#     By treating each keystream position as a single-byte XOR cipher, we can
#     recover the keystream using frequency analysis and decrypt the file.

# === Attack Steps ===
#   1. Read the full ciphertext (encrypted by XOR with a 1000-byte repeating keystream).
#   2. For each key-byte position j in [0..999]:
#        a) Extract the “column” of ciphertext bytes at positions j, j+1000, j+2000, …
#        b) Treat this column as having been XOR’d with a single key-byte K[j].
#        c) Brute-force all 256 possible byte values for K[j], scoring each by English-likeness.
#        d) Select the key-byte that gives the highest English score for the column plaintext.
#   3. Reconstruct the full 1000-byte keystream from the recovered key bytes.
#   4. Decrypt the entire ciphertext by XOR’ing it with the repeating keystream.
#   5. Write the resulting plaintext to disk and inspect for the flag.

# === Flag ===
# CRYPTO25{6afd02cd-127e-4de1-8a97-397668f10141}

import sys

# English character frequencies for scoring plaintext likelihood
# Higher values indicate more common letters in English text
english_frequencies = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074, ' ': 0.13000  # Space is the most common character
}

def score_english(text_bytes: bytes) -> float:
    """
    Scores byte sequence based on resemblance to English text.
    Higher scores indicate higher likelihood of being English.
    
    Scoring logic:
    - Uppercase letters: Convert to lowercase and add frequency score
    - Lowercase letters: Add direct frequency score
    - Space: Add high frequency score (most common character)
    - Whitespace (tab, LF, CR): Small bonus
    - Printable ASCII: Tiny bonus (punctuation/digits)
    - Non-printable: Penalty (indicates non-text content)
    """
    score = 0.0
    for b in text_bytes:
        # Handle uppercase letters (convert to lowercase for frequency)
        if 65 <= b <= 90:  # 'A' to 'Z'
            score += english_frequencies.get(chr(b + 32), 0.0)
        # Handle lowercase letters
        elif 97 <= b <= 122:  # 'a' to 'z'
            score += english_frequencies.get(chr(b), 0.0)
        # Space character (very common in text)
        elif b == 32:
            score += english_frequencies[' ']
        # Common whitespace characters
        elif b in (9, 10, 13):  # Tab, Line Feed, Carriage Return
            score += 0.01
        # Other printable ASCII characters
        elif 33 <= b <= 126:  # Punctuation, digits, symbols
            score += 0.001
        # Non-printable characters (penalized)
        else:
            score -= 0.05
    return score

def crack_single_byte_xor(column_bytes: bytes) -> tuple[int, bytes, float]:
    """
    Finds the most likely key byte for a ciphertext column encrypted with single-byte XOR.
    
    How it works:
    1. Tests all 256 possible key bytes (0-255)
    2. For each candidate key:
        - XORs all bytes in the column with the candidate key
        - Scores the resulting plaintext using English frequency analysis
    3. Returns the key byte that produces the highest-scoring plaintext
    
    Returns tuple: (best_key_byte, decrypted_plaintext, english_score)
    """
    best_key = 0
    best_score = float('-inf')  # Start with lowest possible score
    best_plain = b''
    
    # Try every possible key byte (0-255)
    for k in range(256):
        # Decrypt column with current candidate key
        plain_candidate = bytes(b ^ k for b in column_bytes)
        
        # Score the decrypted text
        s = score_english(plain_candidate)
        
        # Track best result
        if s > best_score:
            best_score = s
            best_plain = plain_candidate
            best_key = k
            
    return best_key, best_plain, best_score

def main():
    """
    Main decryption routine:
    1. Reads encrypted file
    2. Recovers 1000-byte keystream using frequency analysis
    3. Decrypts file with recovered keystream
    4. Saves decrypted file
    """
    # Read ciphertext from file
    try:
        with open('file.enc', 'rb') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print("Error: 'file.enc' not found. Place it in the working directory.")
        sys.exit(1)

    # Encryption parameters (from challenge)
    KEYLEN = 1000
    file_len = len(ciphertext)
    keystream = bytearray(KEYLEN) # Initialize keystream
    
    print(f"[*] Ciphertext length: {file_len} bytes")
    print("[*] Recovering keystream (1000 bytes) via frequency analysis...")
    print("    This takes advantage of the repeating keystream vulnerability")
    print("    Each byte position in the keystream is cracked independently\n")

    # Recover keystream one byte at a time
    for j in range(KEYLEN):
        # Collect all bytes encrypted with keystream[j]
        column_bytes = bytearray()
        idx = j
        while idx < file_len:
            column_bytes.append(ciphertext[idx])
            idx += KEYLEN
        
        # Only process if we have data for this keystream position
        if column_bytes:
            # Crack this column (single-byte XOR)
            key_byte, _, score = crack_single_byte_xor(column_bytes)
            keystream[j] = key_byte
        else:
            # No ciphertext bytes for this position (unlikely with large file)
            keystream[j] = 0

        # Progress updates every 100 bytes
        if (j + 1) % 100 == 0 or j == KEYLEN - 1:
            print(f"    → Recovered {j+1}/1000 keystream bytes")

    # Decrypt entire file using recovered keystream
    plaintext = bytearray(file_len)
    for i in range(file_len):
        # XOR each ciphertext byte with corresponding keystream byte
        # Note: keystream repeats every 1000 bytes (i % KEYLEN)
        plaintext[i] = ciphertext[i] ^ keystream[i % KEYLEN]
    
    # Write decrypted output
    with open('file.txt', 'wb') as f:
        f.write(plaintext)
    print("\n[+] Decryption complete. Output saved to 'file.txt'")
    print("[+] Open file.txt to find the flag!")

if __name__ == '__main__':
    main()
