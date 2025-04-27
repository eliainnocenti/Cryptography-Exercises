# Force Decryption

## Challenge

In this challenge, the server uses AES in CBC mode to encrypt and decrypt user-provided data. The goal is to forge an IV that forces the server to decrypt a ciphertext into a specific value. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **AES-CBC Encryption**: The server encrypts and decrypts 16-byte blocks using AES in CBC mode.
- **Forbidden Value**: The server prevents users from encrypting or using a specific value (`leak`) as the plaintext or IV.
- **IV Manipulation**: By manipulating the IV, we can control the decrypted plaintext.

Key points in `chall.py`:
- The `encrypt` function encrypts user-provided plaintext and returns the IV and ciphertext.
- The `decrypt` function decrypts user-provided ciphertext and IV, then checks if the decrypted value matches the forbidden value (`leak`).

## Main Logic

The main logic for solving this challenge is:
1. Encrypt a block of null bytes to obtain the original IV and ciphertext.
2. XOR the original IV with the forbidden value to compute the forged IV.
3. Send the forged IV and the original ciphertext to the server to force the decryption to the forbidden value.
4. Retrieve the flag from the server.

## How to Solve It

To solve the challenge:
1. Connect to the server and encrypt 16 null bytes to get the original IV and ciphertext.
2. Compute the forged IV by XORing the original IV with the forbidden value:
   - `forged_IV = original_IV ⊕ forbidden_value`
   - This ensures that the decrypted value matches the forbidden value.
3. Send the forged IV and the original ciphertext to the server.
4. Retrieve the flag from the server.

### Error Handling
The `solve.py` script includes error handling for unexpected server responses, such as empty or malformed outputs. This ensures the script can handle edge cases gracefully.

### Retrieving the Flag
The script retrieves the flag from the server's response:
````python
result = s.recv(4096)
print(result.decode())
````

By following this structured approach, the script successfully forces the server to decrypt the ciphertext into the forbidden value and retrieves the flag.
