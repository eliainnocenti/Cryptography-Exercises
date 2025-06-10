# RSA - Level 6

# access the server and get the flag
# nc 130.192.5.212 6646

# === Attack Overview ===
# - Attack Type: RSA Decryption Oracle & Blinding Attack
# - Implementation Attack
# - Weakness: Improper RSA service implementation allowing decryption without access control.
# - Brief Attack Description:
#     This attack exploits the RSA service's ability to decrypt ciphertexts
#     without proper access controls. By using RSA blinding, we can trick
#     the server into decrypting a target ciphertext disguised as a different value.

# === Attack Steps ===
#  1. Connect to the server and read the flag ciphertext `c`.
#  2. Choose a small blinding factor `r` (e.g., 2).
#  3. Ask the server to encrypt `r` to obtain `rᵉ mod n`.
#  4. Forge `c' = c · rᵉ` and ask the server to decrypt it, yielding `m·r`.
#  5. Recover `m = (m·r) // r` (since m·r < n, integer division is exact).
#  6. Convert `m` to bytes to reveal the flag.

# === Flag ===
# CRYPTO25{4701ecda-eaf6-4a7a-9e43-29cdf914e9ff}

from pwn import remote
from Crypto.Util.number import long_to_bytes

# Server configuration
HOST = '130.192.5.212'
PORT = 6646

# Step 1: Connect to the server and get the encrypted flag
conn = remote(HOST, PORT)
c = int(conn.recvline().strip()) # The encrypted flag

# Step 2: Choose a small blinding factor (r=2 ensures m * r < n for typical flags)
r = 2

# Step 3: Request encryption of the blinding factor
conn.sendline(f"e{r}".encode())    # Convert string to bytes
r_e = int(conn.recvline().strip()) # r^e mod n

# Step 4: Forge the blinded ciphertext: c' = c * (r^e) mod n
c_prime = c * r_e # Server will reduce mod n during decryption

# Step 5: Request decryption of the forged ciphertext
conn.sendline(f"d{c_prime}".encode())    # Convert string to bytes
m_times_r = int(conn.recvline().strip()) # Decrypted result = m * r

# Step 6: Unblind to recover the original message m
m = m_times_r // r # Integer division is exact since m * r < n

# Step 7: Convert the integer to bytes and print the flag
flag = long_to_bytes(m)
print(flag.decode())

conn.close()
