# Long Secret Message

## Challenge

In this challenge, the server encrypts a long plaintext message line by line using ChaCha20 encryption. The goal is to decrypt the ciphertext and extract the flag, which is embedded in the plaintext. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **ChaCha20 Encryption**: The server encrypts each line of the plaintext using ChaCha20 with a fixed key and nonce.
- **Line-by-Line Encryption**: Each line of the plaintext is encrypted independently.
- **Known Plaintext**: The plaintext file is partially known, allowing us to derive the keystream.

Key points in `chall.py`:
- The `key` and `nonce` are fixed for all lines, making the keystream predictable.
- Each line of the plaintext is encrypted independently, allowing us to derive the keystream from known plaintext.

## Main Logic

The main logic for solving this challenge is:
1. Use the known plaintext to derive the keystream.
2. Decrypt the ciphertext using the derived keystream.
3. Search the decrypted plaintext for the flag.

## How to Solve It

To solve the challenge:
1. **Read Files**: Read the ciphertext and plaintext files.
2. **Derive Keystream**: XOR a ciphertext line with its corresponding plaintext line to derive the keystream.
3. **Decrypt Ciphertext**: Use the derived keystream to decrypt all ciphertext lines.
4. **Extract Flag**: Search the decrypted plaintext for the flag.

### Reading Files
The script reads the ciphertext and plaintext files:
````python
ciphertexts = read_ciphertext("hacker-manifesto.enc")
plaintexts = read_plaintext("hacker-manifesto.txt")
````

### Deriving the Keystream
The script derives the keystream by XOR-ing a ciphertext line with its corresponding plaintext line:
````python
keystream = derive_keystream_line(ct_line, pt_line)
````

### Decrypting the Ciphertext
The script decrypts all ciphertext lines using the derived keystream:
````python
decrypted = decrypt_with_keystream(ciphertexts, keystream)
````

### Extracting the Flag
The script searches the decrypted plaintext for the flag:
````python
flag = extract_flag(decrypted)
if flag:
    print(f"[+] FLAG FOUND: {flag}")
````

By following this structured approach, the script successfully decrypts the ciphertext and retrieves the flag.
