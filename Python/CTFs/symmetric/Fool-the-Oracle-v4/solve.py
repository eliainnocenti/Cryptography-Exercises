# Fool the Oracle v4

# ...even harder with this one...
# nc 130.192.5.212 6544

# === Attack Overview ===
# - Attack Type: Byte-at-a-time ECB Decryption with Unknown Random Prefix (ECB Padding Oracle)
# - Implementation Attack
# - Weakness: Oracle leaks ciphertext for arbitrary plaintext, with fixed but unknown random prefix
# - Brief Attack Description:
#     This attack exploits the ability to encrypt arbitrary plaintexts under ECB mode,
#     even with an unknown random prefix. By aligning controlled input and using
#     byte-at-a-time guessing, the attacker can recover the secret flag.

# === Attack Steps ===
#   1. Detect the length of the unknown random prefix by sending repeated blocks
#      until two identical ciphertext blocks appear (prefix alignment).
#   2. Compute pad_len = number of bytes needed so that controlled input
#      aligns the next unknown plaintext byte at the end of an AES block.
#   3. For each flag byte:
#        a) Send prefix + known_bytes + guess_byte and compare the target block
#        b) When a guess produces the same block as the real encryption, record it
#   4. Continue until the closing “}” is recovered.
#   5. Strip any garbage before “CRYPTO25” and print the flag.

# === Flag ===
# CRYPTO25{f4e6e2e2-2e2e-4e7e-9e6e-2e6e6e6e6e6e}

# === Differences from Previous Versions ===
# Fool the Oracle v1 -> No Padding
# Fool the Oracle v2 -> Padding with known length (5 bytes)
# Fool the Oracle v3 -> Random length padding (1-15 bytes)

from pwn import remote

# Server configuration
HOST = '130.192.5.212'
PORT = 6544

BLOCK_SIZE = 16 # AES block size

def get_block(ciphertext: bytes, index: int) -> bytes:
    """Extract a specific block from ciphertext"""
    start = index * BLOCK_SIZE
    return ciphertext[start:start+BLOCK_SIZE]

def connect_to_server():
    """Establish connection and consume initial prompt"""
    io = remote(HOST, PORT)
    io.recvuntil(b"> ")
    return io

def encrypt_data(io, data: bytes) -> bytes:
    """Request encryption of data and return ciphertext"""
    io.sendline(b"enc")
    io.recvuntil(b"> ")
    io.sendline(data.hex().encode())
    ct_hex = io.recvline().strip().decode()
    io.recvuntil(b"> ")
    return bytes.fromhex(ct_hex)

def find_prefix_length(io) -> int:
    """Determine minimal input length for block alignment"""
    for pad_len in range(32):  # Try padding lengths 0-31
        # Send test pattern: padding + 32 identical bytes
        test_data = b"A" * pad_len + b"B" * 32
        ciphertext = encrypt_data(io, test_data)
        
        # Check for consecutive identical blocks
        for i in range(0, len(ciphertext) - BLOCK_SIZE, BLOCK_SIZE):
            if ciphertext[i:i+BLOCK_SIZE] == ciphertext[i+BLOCK_SIZE:i+2*BLOCK_SIZE]:
                print(f"[+] Alignment found at pad length: {pad_len}")
                return pad_len
    raise RuntimeError("Failed to find block alignment")

def recover_flag(io, pad_len: int) -> bytes:
    """Recover flag byte-by-byte using ECB oracle"""
    known_flag = b""
    flag_start_index = None
    
    while True:
        # Calculate prefix to position next byte at block end
        align_bytes = BLOCK_SIZE - 1 - (len(known_flag) % BLOCK_SIZE)
        prefix_len = align_bytes + pad_len
        prefix = b"A" * prefix_len
        
        # Get reference ciphertext and target block
        ref_ciphertext = encrypt_data(io, prefix)
        target_block_idx = (prefix_len + len(known_flag)) // BLOCK_SIZE
        target_block = get_block(ref_ciphertext, target_block_idx)
        
        # Brute-force next byte (0-255)
        found_byte = False
        for byte_val in range(256):
            # Build guess with known bytes and current byte candidate
            guess = prefix + known_flag + bytes([byte_val])
            guess_ciphertext = encrypt_data(io, guess)
            guess_block = get_block(guess_ciphertext, target_block_idx)
            
            if guess_block == target_block:
                known_flag += bytes([byte_val])
                print(f"[+] Progress: {known_flag}")
                found_byte = True
                
                # Detect flag start pattern
                if flag_start_index is None and b"CRYPTO25{" in known_flag:
                    flag_start_index = known_flag.index(b"CRYPTO25{")
                    print(f"[+] Flag starts at index: {flag_start_index}")
                
                # Extract full flag once we have enough bytes
                if flag_start_index is not None and len(known_flag) >= flag_start_index + 46:
                    return known_flag[flag_start_index:flag_start_index+46]
                break
        
        if not found_byte:
            raise RuntimeError(f"Failed to recover byte at position {len(known_flag)}")

def main():
    io = connect_to_server()
    
    try:
        # Step 1: Find alignment padding length
        pad_len = find_prefix_length(io)
        print(f"[*] Using pad length: {pad_len}")
        
        # Step 2: Recover flag
        flag = recover_flag(io, pad_len)
        print(f"\n[+] FLAG: {flag.decode()}")
    
    finally:
        io.close()

if __name__ == "__main__":
    main()
