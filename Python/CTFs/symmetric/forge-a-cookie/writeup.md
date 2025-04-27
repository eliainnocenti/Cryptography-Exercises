# Forge a Cookie

## Challenge

In this challenge, the server encrypts a JSON object containing a username using ChaCha20 encryption. The goal is to forge a token that grants admin privileges by manipulating the ciphertext and nonce. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **ChaCha20 Encryption**: The server uses ChaCha20 with a random nonce to encrypt a JSON object containing the username.
- **Token Structure**: The token consists of the base64-encoded nonce and ciphertext, separated by a dot (`.`).
- **Keystream Recovery**: By sending a known username, we can recover the keystream and use it to forge a valid token for an admin user.

Key points in `chall.py`:
- The `get_user_token` function generates a token for a given username by encrypting a JSON object.
- The `check_user_token` function decrypts the token and verifies if the user has admin privileges.
- The `get_flag` function checks if the user is an admin and, if so, reveals the flag.

## Main Logic

The main logic for solving this challenge is:
1. Send a known username to the server to obtain a token.
2. Decrypt the token to recover the keystream using the known plaintext (the JSON object for the username).
3. Use the recovered keystream to encrypt a forged JSON object with admin privileges.
4. Construct a valid token using the original nonce and the forged ciphertext.
5. Send the forged token to the server to retrieve the flag.

## How to Solve It

To solve the challenge:
1. Connect to the server and send a known username to get a token.
2. Decode the token to extract the nonce and ciphertext.
3. XOR the ciphertext with the known plaintext to recover the keystream:
   - `keystream = ciphertext ⊕ known_plaintext`
   - This works because ChaCha20 encryption is a stream cipher, and the ciphertext is the XOR of the plaintext and the keystream.
4. Use the keystream to encrypt a forged JSON object with admin privileges.
5. Construct the forged token and send it to the server to retrieve the flag.

### Error Handling
The `solve.py` script includes error handling for unexpected server responses, such as empty or malformed outputs. This ensures the script can handle edge cases gracefully.

### Recovering the Keystream
The script recovers the keystream by XORing the ciphertext with the known plaintext:
````python
known_plaintext = json.dumps({"username": known_username}).encode()
keystream = xor(ciphertext, known_plaintext)
````

### Forging the Ciphertext
The script uses the recovered keystream to encrypt a forged JSON object:
````python
ks = keystream[:len(forged_plaintext)]
forged_ciphertext = xor(forged_plaintext, ks)
````

### Constructing the Forged Token
The script constructs the forged token using the original nonce and the forged ciphertext:
````python
forged_token = f"{base64.b64encode(nonce).decode()}.{base64.b64encode(forged_ciphertext).decode()}"
````

### Sending the Forged Token
The script sends the forged token to the server to retrieve the flag:
````python
s.sendall((forged_token + "\n").encode())
result = s.recv(4096)
print(result.decode())
````

By following this structured approach, the script successfully forges a token and retrieves the flag.
