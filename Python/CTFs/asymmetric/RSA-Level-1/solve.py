# RSA - Level 1

# The attached file contains the code and the output. Use them to get the flag...

"""
Solve RSA CTF via FactorDB Python client:
Uses the provided modulus n and ciphertext c from the challenge.

Given:
  n = 176278749487742942508568320862050211633
  c = 46228309104141229075992607107041922411

Uses factordb-python to fetch factors, computes the private key,
decrypts c, and prints the flag as ASCII.
"""

from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB

# Challenge-provided values
n = 176278749487742942508568320862050211633
c = 46228309104141229075992607107041922411
E = 65537

def fetch_factors_with_client(n):
    """
    Connects to FactorDB and retrieves the prime factors p and q of n.
    """
    f = FactorDB(n)
    f.connect()
    
    factors = f.get_factor_list()
    
    if len(factors) != 2:
        raise ValueError(f"Expected 2 prime factors but got: {factors}")
    
    p, q = map(int, factors)
    
    return p, q

def main():
    # Step 1: retrieve p, q
    p, q = fetch_factors_with_client(n)

    # Ensure p < q for consistency
    if p > q:
        p, q = q, p

    # Step 2: compute φ(n)
    phi = (p - 1) * (q - 1)

    # Step 3: compute modular inverse d = E^{-1} mod φ(n)
    d = pow(E, -1, phi)

    # Step 4: RSA decryption
    m = pow(c, d, n)

    # Step 5: convert integer to bytes and print flag
    flag = long_to_bytes(m)
    print(flag.decode())

if __name__ == "__main__":
    main()
