# Fool the Oracle v3

## Challenge

In this challenge, the server encrypts user-provided data concatenated with random padding and a secret flag using AES in ECB mode. The goal is to recover the flag by exploiting the deterministic nature of ECB encryption. The server provides an encryption oracle that allows you to encrypt arbitrary data and observe the resulting ciphertext.

The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:
- The server encrypts user-provided data concatenated with random padding and the flag using AES in ECB mode.
- The payload is padded to match the AES block size before encryption.
- The user can repeatedly query the encryption oracle to analyze the ciphertext.

Key points in `chall.py`:
- **AES in ECB Mode**: Encrypts blocks independently, so identical plaintext blocks produce identical ciphertext blocks.
- **Random Padding**: Random padding of length between 1 and 15 bytes is prepended to the user-provided data, making it necessary to align the input correctly.
- **Byte-at-a-Time Attack**: By carefully crafting inputs, you can recover the flag one byte at a time.

## Main Logic

The main logic for solving this challenge is:
1. Find the alignment of the random padding to control the input blocks.
2. Leverage the deterministic nature of ECB mode to recover the flag byte by byte.
3. Use a known prefix to align the flag bytes at the end of a block.
4. Compare the ciphertext of the known prefix concatenated with a guessed byte to the ciphertext of the actual flag.

## How to Solve It

To solve the challenge:
1. **Find Prefix Alignment**: Determine the number of padding bytes needed to align the input so that controlled blocks are identical.
2. **Align the Flag**: Use the alignment information to position the flag bytes at the end of a block.
3. **Brute-Force Bytes**: Brute-force each byte of the flag by comparing ciphertext blocks.
4. **Repeat**: Repeat this process until the entire flag is recovered.

### Finding Prefix Alignment
The script determines the number of padding bytes needed to align the input so that controlled blocks are identical:
````python
def find_prefix_alignment(conn):
    for pad_len in range(0, BLOCK_SIZE):
        probe = b'A' * pad_len + b'B' * (BLOCK_SIZE * 2)
        ct_hex = get_ciphertext_hex(conn, probe.hex())
        ct = bytes.fromhex(ct_hex)
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i+1]:
                return pad_len, i
````

### Aligning the Flag
The script uses the alignment information to position the flag bytes at the end of a block:
````python
filler = (BLOCK_SIZE - 1 - (len(recovered) % BLOCK_SIZE))
payload = b'A' * (pad_len + filler)
````

### Brute-Forcing Bytes
The script brute-forces each byte of the flag by comparing ciphertext blocks:
````python
for b in range(256):
    guess = payload + recovered + bytes([b])
    guess_ct = bytes.fromhex(get_ciphertext_hex(conn, guess.hex()))
    guess_block = guess_ct[block_idx*BLOCK_SIZE : (block_idx+1)*BLOCK_SIZE]
    if guess_block == target_block:
        recovered += bytes([b])
        char = chr(b) if 32 <= b < 127 else '?'
        sys.stdout.write(char)
        sys.stdout.flush()
        break
````

### Retrieving the Flag
After recovering all bytes of the flag, the script decodes and prints it:
````python
print(f"[+] Recovered flag: {flag.decode()}")
````

By following this structured approach, the script successfully recovers the flag.
