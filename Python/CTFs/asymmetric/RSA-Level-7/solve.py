# RSA - Level 7

# nc 130.192.5.212 6647

"""
Recover RSA plaintext via LSB oracle (Bleichenbacher's attack):

Connect to the remote service, which provides:
  n
  c0 = m^e mod n

Then repeatedly accepts ciphertexts and returns the least significant bit (LSB) of the decrypted value.

We use a binary search on the interval [0, n) for m, adjusting the ciphertext by multiplying by (2^e)^i, 
querying the LSB each time to narrow the interval.
"""

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
    two_e = pow(2, E, n)

    # Interval [low, high)
    low, high = Fraction(0), Fraction(n)

    # Initialize progress bar
    progress = log.progress('Bits')

    # Perform binary search using fractions
    for i in range(n.bit_length()):
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
    flag = long_to_bytes(m).decode()
    log.success(f"Flag: {flag}")

    conn.close()

if __name__ == '__main__':
    main()
