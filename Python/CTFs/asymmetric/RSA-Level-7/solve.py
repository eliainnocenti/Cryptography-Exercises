# RSA - Level 7

# nc 130.192.5.212 6647

# === Attack Overview ===
# - Attack Type: LSB Oracle Attack (parity‐oracle based binary search)
# - Implementation Attack
# - Weakness: The server provides an oracle that reveals the least significant bit (LSB)
# - Brief Attack Description:
#     This attack exploits a decryption oracle that reveals the least significant bit
#     of the plaintext when given a ciphertext. By repeatedly querying this oracle
#     with carefully crafted ciphertexts, we can perform a binary search to recover
#     the entire plaintext message bit by bit. This is a known vulnerability in RSA
#     implementations where the oracle leaks information about the plaintext
#     through the parity of the decrypted ciphertexts, allowing an attacker to
#     reconstruct the plaintext without needing to factor the modulus or know the private key.

# === Attack Steps ===
#  1. Connect to the server and read the modulus n and ciphertext c.
#  2. Precompute 2^e mod n for blinding successive queries.
#  3. For each bit, multiply ciphertext by 2^e and query the LSB oracle.
#  4. Use binary search interval refinement based on the returned bit.
#  5. After all bits, convert the recovered plaintext to bytes.

# === Flag ===
# CRYPTO25{b4b6d1f1-929c-4a41-9900-51091ea9b258}

from pwn import remote, log
from fractions import Fraction
from Crypto.Util.number import long_to_bytes

# Server configuration
HOST = '130.192.5.212'
PORT = 6647

# RSA public exponent
E = 65537

def main():
    # Connect to oracle
    conn = remote(HOST, PORT)

    # Receive modulus n and initial ciphertext c
    n = int(conn.recvline().strip())
    c = int(conn.recvline().strip())

    # Precompute multiplier: 2^e mod n
    two_e = pow(2, E, n) # ~ Blinding factor for each query, because the server print(dec%2)

    # Interval [low, high)
    low, high = Fraction(0), Fraction(n)

    # Initialize progress bar
    progress = log.progress('Bits')

    # For each bit in the binary representation of n
    # we can recover the plaintext bit by bit

    # Perform binary search using fractions
    for i in range(n.bit_length()):
        # So this is like doing 2*m, where m is the plaintext
        # With this iteration we are effectively shifting the plaintext left by one bit
        c = (c * two_e) % n # Blind ciphertext

        # Get parity bit from the oracle
        conn.sendline(str(c).encode())
        bit = int(conn.recvline().strip())

        mid = (low + high) / 2
        if bit == 0:
            high = mid # Plaintext is in the lower half
        else:
            low = mid  # Plaintext is in the upper half
        
        # Update progress line (overwrites itself)
        progress.status(f"{i+1}/{n.bit_length()} (bit={bit})")

    progress.success('Done')
    
    # Final plaintext is the integer part of high
    m = int(high)
    flag = long_to_bytes(m)
    log.success(f"Flag: {flag.decode()}")

    conn.close()

if __name__ == '__main__':
    main()
