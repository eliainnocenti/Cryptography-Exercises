# Decrypt the Flag!

## Challenge

In this challenge, the server encrypts a secret flag using ChaCha20 with a random nonce. The goal is to recover the flag by brute-forcing the random seed used to generate the nonce. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **ChaCha20 Encryption**: The server uses ChaCha20 with a random nonce to encrypt the flag.
- **Seed-Based Nonce**: The server initializes the random number generator with a user-provided seed to generate the nonce.
- **Known Plaintext**: The server allows users to encrypt additional messages, which can be used to recover the keystream.
- **Nonce Update**: After each encryption, the nonce is updated to prevent reusing the same keystream for different messages.

Key points in `chall.py`:
- The `encrypt_and_update` function encrypts a message using ChaCha20 and updates the nonce.
- The `main` function initializes the random seed, encrypts the flag, and allows users to encrypt additional messages.

## Main Logic

The main logic for solving this challenge is:
1. Brute-force the seed used to initialize the random number generator.
2. For each seed, connect to the server and retrieve the encrypted flag.
3. Send a known plaintext to recover the keystream.
4. Use the keystream to decrypt the flag.

## How to Solve It

To solve the challenge:
1. Iterate through all possible seeds and connect to the server.
2. Retrieve the encrypted flag from the server.
3. Send a known plaintext to recover the keystream.
4. Use the keystream to decrypt the flag.
5. Check if the decrypted flag contains the expected keyword.

### Recovering the Keystream
The keystream is recovered by XORing the known plaintext with its corresponding ciphertext:
````python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

known, known_ct = send_known_plaintext(conn, len(flag_ct))
keystream = xor_bytes(known_ct, known)
````

### Decrypting the Flag
The flag is decrypted by XORing the encrypted flag with the recovered keystream:
````python
flag_plain = xor_bytes(flag_ct, keystream)
````

By following this structured approach, the script successfully decrypts the flag.
