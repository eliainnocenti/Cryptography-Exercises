# Back to the Future

## Challenge

In this challenge, the server encrypts a cookie containing user information using ChaCha20 encryption. The goal is to forge a cookie with a manipulated expiration timestamp to retrieve the flag. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **ChaCha20 Encryption**: The server uses ChaCha20 with a random nonce to encrypt cookies.
- **Cookie Structure**: The cookie contains user information in the format `username=<username>&expires=<timestamp>&admin=<0/1>`.
- **Expiration Validation**: The server validates the expiration timestamp against an admin expiration date.

Key points in `chall.py`:
- The `login` endpoint generates a cookie for the user by encrypting the cookie string.
- The `flag` endpoint decrypts the cookie, parses it, and checks if the user is an admin with a valid expiration timestamp.

## Main Logic

The main logic for solving this challenge is:
1. Log in as admin to retrieve the nonce and derive the keystream.
2. Forge a cookie with a manipulated expiration timestamp.
3. Brute-force the expiration timestamp until the server accepts the cookie and returns the flag.

## How to Solve It

To solve the challenge:
1. **Log In**: Send a login request as admin to retrieve the nonce and derive the keystream.
2. **Forge Cookie**: Use the derived keystream to encrypt a cookie with a guessed expiration timestamp.
3. **Brute-Force Expiration**: Iterate through possible expiration timestamps until the server returns the flag.

### Logging In
The script logs in as admin to retrieve the nonce and derive the keystream:
````python
params = {"username": "admin", "admin": "1"}
resp = session.get(f"{URL}/login", params=params)
nonce = to_bytes(resp.json().get("nonce"))
ciphertext = to_bytes(resp.json().get("cookie"))
plaintext = f"username=admin&expires={expires}&admin=1".encode()
keystream = xor_bytes(ciphertext, plaintext)
````

### Forging the Cookie
The script forges a cookie with a guessed expiration timestamp:
````python
cookie_str = f"username=admin&expires={expire_guess}&admin=1"
cookie_bytes = cookie_str.encode()
forged_cipher = xor_bytes(cookie_bytes, keystream)
````

### Brute-Forcing Expiration
The script iterates through possible expiration timestamps to retrieve the flag:
````python
for days_ago in range(min_days, max_days + 1):
    guessed_admin_expire = now - days_ago * 24 * 3600
    expire_guess = guessed_admin_expire + offset_days * 24 * 3600
    text = forge_cookie_and_request(session, nonce, keystream, expire_guess)
    if "flag" in text.lower():
        print(f"[+] Flag retrieved: {text}")
        break
````

By following this structured approach, the script successfully retrieves the flag.
