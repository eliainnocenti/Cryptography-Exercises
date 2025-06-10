# decrypt it, if you are fast enough!

# I'm reusing the already reused message... ......read the challenge code and find the flag!
# nc 130.192.5.212 6562

# === Attack Overview ===
# - Attack Type: ChaCha20 Nonce-Reuse Stream Cipher Keystream Recovery
# - Implementation Attack
# - Weakness: Nonce reuse with the same key in stream cipher
# - Brief Attack Description:
#     This attack exploits the reuse of a nonce in the ChaCha20 stream cipher.
#     By encrypting a known plaintext and receiving its ciphertext under the same
#     key and nonce as the flag, the keystream can be recovered and used to decrypt
#     the flag ciphertext.

# === Attack Steps ===
#   1. Connect to the service and request encryption of a known plaintext.
#   2. Receive both the ciphertext of the known plaintext and the flag ciphertext
#      under the same (unknown) key and reused nonce.
#   3. Derive the keystream: keystream = ct_known ⊕ pt_known.
#   4. Recover the flag: pt_flag = ct_flag ⊕ keystream.
#   5. If flag not found, repeat with a fresh connection (nonce may rotate each run).

# === Flag ===
# CRYPTO25{23ae15cf-c924-416c-b44d-fde94f18cc0c}

from pwn import remote
import time

# Server configuration
HOST = "130.192.5.212"
PORT = 6562

# Known plaintext (100 'A's) to cover maximum flag length
known_plain = b'A' * 100

# Maximum attempts to account for time synchronization issues
max_attempts = 30

for attempt in range(max_attempts):
    try:
        # Connect to server
        io = remote(HOST, PORT)
        
        # Step 1: Encrypt known plaintext
        io.sendlineafter(b"Want to encrypt? (y/n/f)", b'y')
        io.sendlineafter(b"> ", known_plain)
        ct_known_hex = io.recvline().strip()
        ct_known = bytes.fromhex(ct_known_hex.decode())
        
        # Step 2: Immediately request flag encryption
        io.sendlineafter(b"Want to encrypt something else? (y/n/f)", b'f')
        ct_flag_hex = io.recvline().strip()
        ct_flag = bytes.fromhex(ct_flag_hex.decode())
        
        io.close()

        # Step 3: Recover keystream using known plaintext
        keystream = bytes([ck ^ kp for ck, kp in zip(ct_known, known_plain)])
        
        # Step 4: Decrypt flag ciphertext
        flag_bytes = bytes([cf ^ ks for cf, ks in zip(ct_flag, keystream[:len(ct_flag)])])

        # I can perform this because the nonce is not changed since the server is seeding with the current time.
        # Performing these operations in the same second should yield the same keystream.
        
        # Step 5: Check for flag pattern
        if b'CRYPTO25{' in flag_bytes:
            # Extract flag by decoding bytes
            flag = flag_bytes.decode(errors='ignore')
            print(f"Flag found on attempt {attempt+1}: {flag}")
            break
        else:
            print(f"Attempt {attempt+1}: Failed - operations likely occurred in different seconds")
    
    except Exception as e:
        print(f"Attempt {attempt+1} failed with error: {e}")
        time.sleep(0.1)  # Brief pause between attempts
else:
    print("Flag not found after 30 attempts. Try increasing max_attempts")
