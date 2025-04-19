# Fool the Oracle

# you have the code, guess the flag
# nc 130.192.5.212 6541

import sys
from pwn import remote

# Remote server info
HOST = "130.192.5.212"
PORT = 6541

BLOCK_SIZE = 16  # AES block size in bytes

def get_ciphertext(conn, payload_hex: str) -> bytes:
    """
    Send the `enc` command and then our hex‑encoded payload,
    return the raw ciphertext bytes (no hex).
    """
    conn.recvuntil(b"> ") # Wait for menu prompt
    conn.sendline(b"enc") # Tell it we want to encrypt
    conn.recvuntil(b"> ") # Wait for the input prompt
    conn.sendline(payload_hex.encode()) # Send our hex payload
    ct_hex = conn.recvline().strip().decode() # Read back one line (the hex ciphertext)
    return bytes.fromhex(ct_hex)

def byte_at_a_time_ecb():
    # How long is the flag? Per the assertion in chall.py:
    # len(flag) == len("CRYPTO25{}") + 36
    flag_len = len("CRYPTO25{}") + 36
    recovered = b""

    # Open one connection and keep it
    conn = remote(HOST, PORT)

    print(f"[*] Starting ECB byte‑at‑a‑time (flag length = {flag_len})\n")

    for i in range(flag_len):
        # Compute how many 'A's to send so that the next unknown byte
        # of FLAG ends up at the very end of one block.
        pad_len = BLOCK_SIZE - (len(recovered) % BLOCK_SIZE) - 1
        prefix = b"A" * pad_len

        # Pull the oracle output for just the prefix
        ct_full = get_ciphertext(conn, prefix.hex())

        # Which block contains the unknown byte?
        # It's the block index = floor((prefix_length + known_length) / BLOCK_SIZE)
        block_idx = (len(prefix) + len(recovered)) // BLOCK_SIZE
        target_block = ct_full[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

        # Now brute‑force one byte at a time
        found = False
        for b in range(256):
            guess = prefix + recovered + bytes([b])
            guess_ct = get_ciphertext(conn, guess.hex())
            guess_block = guess_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

            if guess_block == target_block:
                recovered += bytes([b])
                sys.stdout.write(chr(b))
                sys.stdout.flush()
                found = True
                break

        if not found:
            print("\n[!] Failed to recover byte", i)
            break

    print("\n\n[+] Done. Recovered flag bytes (raw):", recovered)
    try:
        print("[+] Flag (decoded):", recovered.decode())
    except UnicodeDecodeError:
        print("[!] Warning: could not UTF‑8 decode all bytes.")

    conn.close()

if __name__ == "__main__":
    byte_at_a_time_ecb()
