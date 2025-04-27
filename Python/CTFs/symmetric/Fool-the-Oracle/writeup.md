# Fool the Oracle

## Challenge

In this challenge, the server encrypts user-provided data concatenated with a secret flag using AES in ECB mode. The goal is to recover the flag by exploiting the deterministic nature of ECB encryption. The server provides an encryption oracle that allows you to encrypt arbitrary data and observe the resulting ciphertext.

The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:
- The server encrypts user-provided data concatenated with the flag using AES in ECB mode.
- The flag is appended to the user input before encryption.
- The payload is padded to match the AES block size before encryption.
- The user can repeatedly query the encryption oracle to analyze the ciphertext.

Key points in `chall.py`:
- **AES in ECB Mode**: Encrypts blocks independently, so identical plaintext blocks produce identical ciphertext blocks.
- **Byte-at-a-Time Attack**: By carefully crafting inputs, you can recover the flag one byte at a time.

## Main Logic

The main logic for solving this challenge is:
1. Leverage the deterministic nature of ECB mode to recover the flag byte by byte.
2. Use a known prefix to align the flag bytes at the end of a block.
3. Compare the ciphertext of the known prefix concatenated with a guessed byte to the ciphertext of the actual flag.

## How to Solve It

To solve the challenge:
1. Determine the block size of the encryption by observing how the ciphertext length changes with input length.
2. Use a known prefix to align the flag bytes at the end of a block.
3. Identify the block containing the unknown byte by calculating the block index:
   - `block_idx = floor((prefix_length + known_length) / BLOCK_SIZE)`
4. Brute-force each byte of the flag by comparing the ciphertext of the known prefix concatenated with a guessed byte to the ciphertext of the actual flag.
5. Repeat this process until the entire flag is recovered.

### Determining the Block Size
The script determines the block size by observing how the ciphertext length changes with input length:
````python
block_size = 16  # AES block size
````

### Aligning the Flag
The script uses a known prefix to align the flag bytes at the end of a block:
````python
pad_len = BLOCK_SIZE - (len(recovered) % BLOCK_SIZE) - 1
prefix = b"A" * pad_len
````

### Brute-Forcing Bytes
The script brute-forces each byte of the flag by comparing ciphertext blocks:
````python
for b in range(256):
    guess = prefix + recovered + bytes([b])
    guess_ct = get_ciphertext(conn, guess.hex())
    guess_block = guess_ct[block_idx*BLOCK_SIZE:(block_idx+1)*BLOCK_SIZE]

    if guess_block == target_block:
        recovered += bytes([b])
        sys.stdout.write(chr(b))
        sys.stdout.flush()
        break
````

By following this structured approach, the script successfully recovers the flag.
