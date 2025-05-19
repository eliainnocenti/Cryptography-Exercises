# RSA - Level 5

# You have the code, access the server and get the flag!
# nc 130.192.5.212 6645

"""
Exploit the RSA decryption oracle via multiplicative blinding without repeated queries:

The server prints:
  n
  c0 = pow(m, e, n)  # ciphertext of the hidden flag

Then it accepts a single input:
  'd<integer>' -> decryption oracle: pow(x, d, n), but refuses when result equals m.

We locally compute a blinding ciphertext c' = c0 * g^e mod n for a random g, send only this 'd' request,
receive m*g mod n, then unblind to recover m.
"""

import random
from pwn import remote
from Crypto.Util.number import long_to_bytes, inverse

# Server configuration
HOST = '130.192.5.212'
PORT = 6645

# RSA public exponent
E = 65537

def main():
    # Connect and receive n and c0
    conn = remote(HOST, PORT)
    n = int(conn.recvline().strip())
    c0 = int(conn.recvline().strip())

    # Choose a random blinding factor g (not 0,1)
    g = random.randrange(2, n - 1)

    # Compute g^e mod n locally (no encryption query needed)
    ge = pow(g, E, n)

    # Blind the flag ciphertext: c' = c0 * g^e mod n
    c_blind = (c0 * ge) % n

    # Send decryption request for blinded ciphertext
    conn.sendline(f"d{c_blind}".encode())
    m_blind = int(conn.recvline().strip())

    # Unblind: m = (m_blind * g^{-1}) mod n
    m = (m_blind * inverse(g, n)) % n

    # Convert integer to bytes and print flag
    flag = long_to_bytes(m)
    print(flag.decode())
    conn.close()

if __name__ == '__main__':
    main()
