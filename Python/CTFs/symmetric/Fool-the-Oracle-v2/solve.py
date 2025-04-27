# Fool the Oracle v2

# fool this new one...
# nc 130.192.5.212 6542

from pwn import remote
import sys

# Remote server details
HOST = "130.192.5.212"
PORT = 6542

# AES block size
BLOCK_SIZE = 16

# Known flag length from assertion: len("CRYPTO25{}") + 36
FLAG_LEN = 46

def get_ciphertext_hex(conn, payload_hex: str) -> str:
    """
    Send an encryption request and return the resulting ciphertext in hex format.
    """
    try:
        conn.recvuntil(b"> ")
        conn.sendline(b"enc")
        conn.recvuntil(b"> ")
        conn.sendline(payload_hex.encode())
        return conn.recvline().strip().decode()
    except Exception as e:
        print(f"[!] Communication error during encryption: {e}")
        sys.exit(1)

def find_prefix_alignment(conn):
    """
    Find the number of padding bytes needed to align our input
    so that two controlled blocks are identical.
    
    Returns:
        (pad_len, start_block_idx) : tuple(int, int)
    """
    print("[*] Finding prefix alignment...")
    for pad_len in range(0, BLOCK_SIZE):
        # Create payload: pad_len of 'A', then 2 full blocks of 'B'
        data = b'A' * pad_len + b'B' * (BLOCK_SIZE * 2)
        ct_hex = get_ciphertext_hex(conn, data.hex())
        ct = bytes.fromhex(ct_hex)

        # Split ciphertext into blocks
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

        # Look for two identical adjacent blocks
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                print(f"[+] Found alignment: pad_len={pad_len}, start_block={i}")
                return pad_len, i

    print("[!] Failed to find prefix alignment.")
    sys.exit(1)

def recover_flag(conn, pad_len: int, start_block: int) -> bytes:
    """
    Perform byte-at-a-time ECB attack to recover the flag.

    Args:
        conn: Remote connection object.
        pad_len: Padding needed to align controlled input.
        start_block: Starting block index where controlled data appears.

    Returns:
        recovered (bytes): The full recovered flag.
    """
    recovered = b""
    print("[*] Starting flag recovery...")

    for idx in range(FLAG_LEN):
        # Calculate number of 'A's needed: pad_len + filler to align unknown byte at block boundary
        filler = (BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE))
        payload = b'A' * (pad_len + filler)

        # Get real ciphertext block for comparison
        ct_hex = get_ciphertext_hex(conn, payload.hex())
        ct = bytes.fromhex(ct_hex)

        block_idx = start_block + (len(recovered) // BLOCK_SIZE)
        target_block = ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]

        # Try all possible bytes (0-255)
        found = False
        for b in range(256):
            guess_payload = payload + recovered + bytes([b])
            ct_guess_hex = get_ciphertext_hex(conn, guess_payload.hex())
            ct_guess = bytes.fromhex(ct_guess_hex)

            guess_block = ct_guess[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]

            if guess_block == target_block:
                recovered += bytes([b])
                display_char = chr(b) if 32 <= b < 127 else '.'
                sys.stdout.write(display_char)
                sys.stdout.flush()
                found = True
                break

        if not found:
            print(f"\n[!] Failed to recover byte at index {idx}. Exiting.")
            break

    print() # Newline after flag output
    return recovered

def main():
    print(f"[+] Connecting to {HOST}:{PORT}...")
    try:
        conn = remote(HOST, PORT)
    except Exception as e:
        print(f"[!] Failed to connect: {e}")
        sys.exit(1)

    # Find prefix alignment first
    pad_len, start_block = find_prefix_alignment(conn)

    # Start recovering the flag
    flag = recover_flag(conn, pad_len, start_block)

    try:
        decoded_flag = flag.decode('utf-8')
    except UnicodeDecodeError:
        decoded_flag = flag.decode('utf-8', errors='replace')

    print(f"[+] Recovered flag: {decoded_flag}")

    conn.close()
    print("[+] Connection closed.")

if __name__ == '__main__':
    main()
