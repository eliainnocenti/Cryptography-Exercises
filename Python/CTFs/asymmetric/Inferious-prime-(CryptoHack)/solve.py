# Inferious prime (CryptoHack)

# Here is my super-strong RSA implementation, because it's 
# 1600 bits strong it should be unbreakable... at least I think so!

# === Attack Overview ===
# - Attack Type: Factorization of the modulus (via an online database client → FactorDB)
# - Mathematical Attack
# - Weakness: Small Primes
# - Brief Attack Description:
#     This attack exploits the weakness of RSA when small primes are used.
#     The modulus `n` is the product of two primes `p` and `q`. If these primes
#     are small enough, they can be factored using online databases like FactorDB.
#     Once the primes are known, the private key can be reconstructed and
#     the ciphertext can be decrypted using the RSA decryption formula.

# === Attack Steps ===
#  1. Factor the modulus `n` using FactorDB to obtain primes `p` and `q`.
#  2. Compute Euler's totient function `φ(n) = (p-1)(q-1)`.
#  3. Calculate the private exponent `d = e⁻¹ mod φ(n)`.
#  4. Decrypt the ciphertext using `m = c^d mod n`.
#  5. Convert the decrypted integer to bytes to reveal the flag.

# === Flag ===
# CRYPTO25{fh98df62nx1mc}

from Crypto.Util.number import long_to_bytes
from factordb.factordb import FactorDB

# Challenge-provided values
n = 770071954467068028952709005868206184906970777429465364126693
c = 388435672474892257936058543724812684332943095105091384265939
E = 3

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

    # Step 4: decrypt ciphertext: m = c^d mod n
    m = pow(c, d, n)

    # Step 5: convert integer to bytes and print flag
    flag = long_to_bytes(m)
    print(flag.decode())

if __name__ == "__main__":
    main()
