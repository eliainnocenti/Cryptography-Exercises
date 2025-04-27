# Forge Another Cookie

## Challenge

In this challenge, the server encrypts a cookie containing user information using AES in ECB mode. The goal is to forge a cookie that grants admin privileges by manipulating the ciphertext blocks. The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:

- **AES-ECB Encryption**: The server uses AES in ECB mode to encrypt cookies.
- **Cookie Structure**: The cookie contains user information in the format `username=<username>&admin=false`.
- **Block Rearrangement**: By carefully crafting the username, we can align the `admin=true` value into its own block and rearrange the ciphertext blocks to forge a valid admin cookie.

Key points in `chall.py`:
- The `login` function generates a cookie for the user by encrypting the padded cookie string.
- The `get_flag` function decrypts the cookie, parses it, and checks if the user is an admin.
- If the user is an admin, the server reveals the flag.

## Main Logic

The main logic for solving this challenge is:
1. Craft a username that aligns the `admin=true` value into its own AES block.
2. Log in with the crafted username to receive the encrypted cookie.
3. Rearrange the ciphertext blocks to forge a valid admin cookie.
4. Send the forged cookie to the server to retrieve the flag.

## How to Solve It

To solve the challenge:
1. **Craft Username**: Create a username that aligns the `admin=true` value into its own AES block.
2. **Log In**: Send the crafted username to the server and receive the encrypted cookie.
3. **Forge Cookie**: Rearrange the ciphertext blocks to create a valid admin cookie.
4. **Send Forged Cookie**: Send the forged cookie to the server to retrieve the flag.

### Crafting the Username
The script crafts a username that aligns the `admin=true` value into its own AES block:
````python
def create_malicious_username():
    prefix_padding = b"A" * (BLOCK_SIZE - len("username="))
    true_block = pad(b"true", AES.block_size)
    suffix_padding = b"A" * (BLOCK_SIZE - len("&admin="))
    return prefix_padding + true_block + suffix_padding
````

### Logging In
The script sends the crafted username to the server and receives the encrypted cookie:
````python
username = create_malicious_username()
conn.sendlineafter("Username: ", username)
raw_cookie = conn.recvline().strip()
cookie = long_to_bytes(int(raw_cookie))
````

### Forging the Cookie
The script rearranges the ciphertext blocks to create a valid admin cookie:
````python
def forge_cookie(cookie):
    forged = cookie[:16] + cookie[32:48] + cookie[16:32]
    return str(bytes_to_long(forged)).encode()
````

### Sending the Forged Cookie
The script sends the forged cookie to the server to retrieve the flag:
````python
forged_cookie = forge_cookie(cookie)
conn.recvuntil(b'What do you want to do?\n')
conn.sendline(b'flag')
conn.recvuntil(b'Cookie: ')
conn.sendline(forged_cookie)
flag = conn.recv(1024)
print(f"\n[+] Flag: {flag.decode()}")
````

By following this structured approach, the script successfully forges a cookie and retrieves the flag.
