# RSA - Level 5

# You have the code, access the server and get the flag!
# nc 130.192.5.212 6645

# === Attack Overview ===
# - Attack Type: RSA Decryption Oracle & Blinding Attack
# - Implementation Attack
# - Weakness: Improper RSA service implementation allowing decryption without access control.
# - Brief Attack Description:
#     This attack exploits the RSA service's ability to decrypt ciphertexts
#     without proper access controls. By using RSA blinding, we can trick
#     the server into decrypting a target ciphertext disguised as a different value.

# === Attack Steps ===
# 1. Connect to the server and read the modulus n and target ciphertext c.
# 2. Choose a blinding factor s and compute the blinded ciphertext c' = c · s^e mod n.
# 3. Request decryption of c' to obtain the blinded plaintext m' = m · s mod n.
# 4. Unblind by computing m = m' · s^(-1) mod n to recover the original message.
# 5. Convert the recovered message to bytes to reveal the flag.

# === Flag ===
# CRYPTO25{af37efa5-de5b-4de2-adcd-43324caca805}

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
