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

from pwn import remote

from Crypto.Util.number import long_to_bytes

HOST = '130.192.5.212'
PORT = 6647
E = 65537

def main():
    # Connect to oracle
    conn = remote(HOST, PORT)

    # Receive modulus n and initial ciphertext c0
    n = int(conn.recvline().strip())
    c0 = int(conn.recvline().strip())

    # Precompute multiplier: 2^e mod n
    two_e = pow(2, E, n)

    # Interval [low, high)
    low, high = 0, n
    c = c0

    # Perform bit-by-bit reconstruction
    for i in range(n.bit_length()):
        # Shift ciphertext: corresponds to multiplying plaintext by 2
        c = (c * two_e) % n
        conn.sendline(str(c))
        bit = int(conn.recvline().strip())

        mid = (low + high) // 2
        if bit == 0:
            # plaintext*2^(i+1) < n => plaintext < mid
            high = mid
        else:
            # plaintext*2^(i+1) >= n => plaintext >= mid
            low = mid

    # The correct plaintext m lies at the lower bound of [low, high)
    m = low
    
    # Validate: if ending isn't '}', try high-1
    flag_bytes = long_to_bytes(m)
    if not flag_bytes.decode().endswith('}'):
        m = high - 1
        flag_bytes = long_to_bytes(m)

    print(flag_bytes.decode())
    conn.close()

if __name__ == '__main__':
    main()
