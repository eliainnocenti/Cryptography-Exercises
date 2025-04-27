# Guess Mode Double Shot

## Challenge

In this challenge, the server encrypts user-provided data using either ECB or CBC mode. The goal is to determine the encryption mode by analyzing the ciphertext. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **AES Encryption**: The server uses AES in either ECB or CBC mode with a random key.
- **Two Encryption Calls**: The server allows users to encrypt the same plaintext twice.
- **Mode Detection**: The server expects the user to guess the encryption mode based on the ciphertext.

Key points in `chall.py`:
- The `RandomCipherRandomMode` class initializes an AES cipher with a random mode (ECB or CBC).
- The `main` function handles user input and verifies the user's guess.

## Main Logic

The main logic for solving this challenge is:
1. Send the same plaintext twice to the server.
2. Compare the two ciphertexts:
   - **ECB Mode**: Produces identical ciphertexts for identical plaintexts because blocks are encrypted independently.
   - **CBC Mode**: Produces different ciphertexts due to the chaining mechanism, which depends on the previous block's ciphertext.
3. Repeat this process for all challenges to retrieve the flag.

## How to Solve It

To solve the challenge:
1. Connect to the server and send the same plaintext twice.
2. Compare the two ciphertexts to determine the encryption mode.
3. Send the guessed mode to the server.
4. Repeat this process for all challenges to retrieve the flag.

### Error Handling
The `solve.py` script includes error handling for unexpected server responses, such as empty or malformed outputs. This ensures the script can handle edge cases gracefully.

### Detecting the Encryption Mode
The script compares the two ciphertexts to determine the encryption mode:
````python
def is_ecb(ct1: bytes, ct2: bytes) -> bool:
    return ct1 == ct2
````

### Sending the Guessed Mode
The script sends the guessed mode to the server:
````python
conn.sendline(mode_guess.encode())
````

### Retrieving the Flag
The script retrieves the flag after completing all challenges:
````python
flag_line = conn.recvline().decode().strip()
print("[!] " + flag_line)
````

By following this structured approach, the script successfully detects the encryption mode and retrieves the flag.
