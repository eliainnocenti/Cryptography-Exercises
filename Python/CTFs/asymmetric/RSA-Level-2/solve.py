# RSA - Level 2

# See the attachment for the challenge code. The output is:
# 60509355275518728792864353034381323203712352065221533863094540755630035742080855136016830887120470658395455751858380183285852786807229077435165810022519265154399424311072791755790585544921699474779996198610853766677088209156457859301755313246598035577293799853256065979074343370064111263698164125580000165237
# 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274388721345811255801305658387179978736924822440382730114598169989281210266972874387657989210875921956705640740514819089546339431934001119998309992280196600672180116219966257003764871670107271245284636072817194316693323

# === Attack Overview ===
# - Attack Type: Fermat's Factorization (specialized to consecutive primes)
# - Mathematical Attack
# - Weakness: Close Primes
# - Brief Attack Description:
#     Fermat's factorization method is used to factor a composite number n
#     when the two prime factors p and q are close together. The method
#     relies on the fact that if n = p * q, then we can express n as a difference
#     of squares: n = a^2 - b^2 = (a - b)(a + b). By finding integers a and b
#     such that a^2 - n = b^2, we can derive the factors p and q.

# === Attack Steps ===
#  1. Apply Fermat's factorization to find primes p and q from modulus n.
#  2. Compute Euler's totient function φ(n) = (p-1)(q-1).
#  3. Calculate the private exponent d = e⁻¹ mod φ(n).
#  4. Decrypt the ciphertext using m = c^d mod n.
#  5. Convert the decrypted integer to bytes to reveal the flag.

# === Flag ===
# CRYPTO25{b697e692-401f-4070-9f1f-c9dc2e97a7e9}

from Crypto.Util.number import long_to_bytes
from math import isqrt

# Challenge-provided values
n = 60509355275518728792864353034381323203712352065221533863094540755630035742080855136016830887120470658395455751858380183285852786807229077435165810022519265154399424311072791755790585544921699474779996198610853766677088209156457859301755313246598035577293799853256065979074343370064111263698164125580000165237
c = 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274388721345811255801305658387179978736924822440382730114598169989281210266972874387657989210875921956705640740514819089546339431934001119998309992280196600672180116219966257003764871670107271245284636072817194316693323
E = 65537

# We use Fermat's factorization here because it is very effective when the two prime factors of n (p and q) are close together.
# Fermat's method rewrites n as a difference of squares: n = a^2 - b^2 = (a - b)(a + b).
# By searching for an integer a such that a^2 - n is a perfect square, we can quickly recover p and q.
# This attack works because if p and q are close, the value of a will be very close to sqrt(n), making the search fast and practical.

def factor_close_primes(n):
    """
    Factors modulus when primes p and q are consecutive (q = next_prime(p)).
    We can find p by searching around sqrt(n).
    """
    # Approximate starting point = integer sqrt of n
    a = isqrt(n)
    
    # Ensure a*a >= n
    if a * a < n:
        a += 1
    
    # Increase until a divides n
    while n % a != 0:
        a += 1
    
    # a is q (the larger factor), and p = n // q
    q = a
    p = n // q
    
    return p, q

def main():
    # Step 1: factor n
    p, q = factor_close_primes(n)

    # Step 2: compute φ(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)

    # Step 3: compute private exponent d = E^{-1} mod φ(n)
    d = pow(E, -1, phi)

    # Step 4: decrypt ciphertext: m = c^d mod n
    m = pow(c, d, n)

    # Step 5: convert m to bytes and print flag
    flag = long_to_bytes(m)
    print(flag.decode())

if __name__ == "__main__":
    main()