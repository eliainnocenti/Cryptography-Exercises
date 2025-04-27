# forge another cookie

# Needless to say, you need the proper authorization cookie to get the flag
# nc 130.192.5.212 6552

import os
from pwn import *

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad

# Disable pwntools warnings inside IDEs
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

# Remote server details
HOST = "130.192.5.212"
PORT = 6552

# Block size for AES
BLOCK_SIZE = 16

def create_malicious_username():
    """
    Craft a username that aligns "true" in its own AES block.
    """
    prefix_padding = b"A" * (BLOCK_SIZE - len("username="))
    true_block = pad(b"true", AES.block_size)
    suffix_padding = b"A" * (BLOCK_SIZE - len("&admin="))
    return prefix_padding + true_block + suffix_padding

def forge_cookie(cookie):
    """
    Rearrange blocks to forge an authorization cookie:
    - First block: unchanged
    - Second block: block containing "admin=true"
    - Third block: original second block
    """
    if len(cookie) < 48:
        raise ValueError("Cookie too short to forge correctly!")

    forged = cookie[:16] + cookie[32:48] + cookie[16:32]
    return str(bytes_to_long(forged)).encode()

def get_flag(conn, forged_cookie):
    """
    Send the forged cookie to retrieve the flag.
    """
    conn.recvuntil(b'What do you want to do?\n')
    conn.sendline(b'flag')
    conn.recvuntil(b'Cookie: ')
    conn.sendline(forged_cookie)
    flag = conn.recv(1024)
    return flag.decode()

def main():
    try:
        conn = remote(HOST, PORT)
        
        # Step 1: Send crafted username
        username = create_malicious_username()
        conn.sendlineafter("Username: ", username)
        
        # Step 2: Receive original cookie
        raw_cookie = conn.recvline().strip()
        if not raw_cookie:
            raise ValueError("No cookie received from server.")
        
        cookie = long_to_bytes(int(raw_cookie))
        
        # Step 3: Forge the cookie
        forged_cookie = forge_cookie(cookie)

        print(f"\n[*] Forged cookie (hex): {forged_cookie.hex()}")

        # Step 4: Get the flag
        flag = get_flag(conn, forged_cookie)
        print(f"\n[+] Flag: {flag}")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
