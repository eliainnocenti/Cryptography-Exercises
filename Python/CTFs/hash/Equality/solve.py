# Equality

# Find a string that is both the same and different than another string!
# nc 130.192.5.212 6631

"""
solve.py

1. Import and call Collision() to get two MD4-colliding 64-byte messages.
2. Connect to the remote challenge, send these messages as hex, and print the flag.
"""

from pwn import remote
from MD4Collision_Wang import Collision
from hashlib import md5
from Crypto.Hash import MD4

HOST = '130.192.5.212'
PORT = 6631

def main():
    # Step 1: generate collision pair
    m1, m2, h1, h2 = Collision()

    # Print the two messages
    # print("[-] First message:", m1.hex())
    # print("[-] Second message:", m2.hex())

    # Verify MD4 and MD5 hashes
    md4_s1 = MD4.new(m1).hexdigest()
    md4_s2 = MD4.new(m2).hexdigest()
    md5_s1 = md5(m1).hexdigest()
    md5_s2 = md5(m2).hexdigest()

    print(f"MD4(m1): {md4_s1}, MD4(m2): {md4_s2}")
    print(f"MD5(m1): {md5_s1}, MD5(m2): {md5_s2}")

    assert md4_s1 == md4_s2 and md5_s1 != md5_s2, "Invalid collision"

    # Step 2: connect and send
    conn = remote(HOST, PORT)

    conn.recvuntil(b"Enter the first string:")
    conn.sendline(m1.hex().encode())
    
    conn.recvuntil(b"Enter your second string:")
    conn.sendline(m2.hex().encode())

    # Step 3: receive and print flag
    print(conn.recvline(timeout=5).decode().strip())
    conn.close()

if __name__ == '__main__':
    main()
