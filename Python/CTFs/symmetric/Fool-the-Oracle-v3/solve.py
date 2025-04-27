# Fool the Oracle v3

# ..even more complex now...
# nc 130.192.5.212 6543

from pwn import remote
import sys

# Remote server details
HOST = "130.192.5.212"
PORT = 6543

# AES block size
BLOCK_SIZE = 16

# Known flag length from assertion: len("CRYPTO25{}") + 36
FLAG_LEN = 46
# FLAG_LEN = len("CRYPTO25{}") + 36  # 46 bytes

def get_ciphertext_hex(conn, payload_hex: str) -> str:
    """
    Send an encryption request to the remote service and return the resulting ciphertext as a hex string.
    """
    conn.recvuntil(b"> ")
    conn.sendline(b"enc")
    conn.recvuntil(b"> ")
    conn.sendline(payload_hex.encode())
    return conn.recvline().strip().decode()

def find_prefix_alignment(conn):
    """
    Find the number of 'A' bytes needed to align the user-controlled input
    at the beginning of a block after the unknown random prefix.

    Returns:
        pad_len (int): Number of 'A' bytes required for alignment.
        start_block (int): Block index where our controlled input starts.
    """
    print("[*] Finding prefix alignment...")
    for pad_len in range(0, BLOCK_SIZE):
        # Send 'A' * pad_len followed by two full blocks of 'B'
        probe = b'A' * pad_len + b'B' * (BLOCK_SIZE * 2)
        ct_hex = get_ciphertext_hex(conn, probe.hex())
        ct = bytes.fromhex(ct_hex)
        # Split ciphertext into 16-byte blocks
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        # Look for two consecutive identical blocks
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                print(f"[+] Alignment found: pad_len={pad_len}, start_block={i}")
                return pad_len, i
    print("[!] Failed to find prefix alignment.")
    sys.exit(1)

def recover_flag(conn, pad_len: int, start_block: int) -> bytes:
    """
    Perform byte-at-a-time ECB decryption to recover the hidden flag.

    Args:
        conn: Remote connection object.
        pad_len: Number of 'A' bytes needed for alignment.
        start_block: Block index where controlled data begins.

    Returns:
        Recovered flag as bytes.
    """
    recovered = b""
    print("[*] Starting flag recovery...")
    for idx in range(FLAG_LEN):
        # Add enough 'A's to position the unknown byte at the end of a block
        filler = (BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE))
        payload = b'A' * (pad_len + filler)

        # Get the reference ciphertext block for the current known part + next unknown byte
        ct_hex = get_ciphertext_hex(conn, payload.hex())
        ct = bytes.fromhex(ct_hex)
        block_idx = start_block + (len(recovered) // BLOCK_SIZE)
        target_block = ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]

        # Brute-force each possible next byte
        for b in range(256):
            guess = payload + recovered + bytes([b])
            guess_ct = bytes.fromhex(get_ciphertext_hex(conn, guess.hex()))
            guess_block = guess_ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]

            if guess_block == target_block:
                recovered += bytes([b])
                char = chr(b) if 32 <= b < 127 else '?'  # Print nicely if printable
                sys.stdout.write(char)
                sys.stdout.flush()
                break
        else:
            print(f"\n[!] Byte {idx} not found. Exiting.")
            break
    print()
    return recovered

def main():
    """
    Main function to handle connection, alignment, flag recovery, and output.
    """
    print(f"[+] Connecting to {HOST}:{PORT}...")
    conn = remote(HOST, PORT)

    pad_len, start_block = find_prefix_alignment(conn)
    flag = recover_flag(conn, pad_len, start_block)

    try:
        print(f"[+] Recovered flag: {flag.decode()}")
    except:
        print(f"[+] Recovered flag (raw bytes): {flag}")

    conn.close()
    print("[+] Connection closed.")

if __name__ == '__main__':
    main()
