#!/usr/bin/env python3
"""
Common Modulus Attack on RSA

This script demonstrates the common modulus attack, which exploits RSA
implementations that use the same modulus n with different exponents.
When the same message is encrypted with different exponents that are
coprime, the plaintext can be recovered without knowing the private key.

Mathematical Foundation:
Given:
- n = p * q (common modulus)
- e1, e2 (coprime public exponents)
- c1 = m^e1 mod n
- c2 = m^e2 mod n

If gcd(e1, e2) = 1, then there exist integers u, v such that:
u*e1 + v*e2 = 1

The plaintext can be recovered as:
m = c1^u * c2^v mod n
"""

from Crypto.Util.number import getPrime, inverse
import math

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    
    Finds integers x, y such that ax + by = gcd(a, b).
    
    Args:
        a (int): First integer
        b (int): Second integer
        
    Returns:
        tuple: (gcd, x, y) where gcd = ax + by
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, y, x = extended_gcd(b % a, a)
        return (gcd, x - (b // a) * y, y)


def demonstrate_common_modulus_attack():
    """
    Demonstrate the common modulus attack on RSA.
    
    This function creates a vulnerable RSA setup where the same modulus
    is used with different exponents, then shows how to recover the
    plaintext without knowing the private key.
    """
    print("=== Common Modulus Attack on RSA ===")
    print("This attack exploits RSA systems that reuse the same modulus")
    
    # Generate RSA parameters
    n_len = 1024
    
    print(f"\nGenerating RSA parameters ({n_len}-bit modulus)...")
    p1 = getPrime(n_len)
    p2 = getPrime(n_len)
    n = p1 * p2
    
    print(f"Prime p1: {p1}")
    print(f"Prime p2: {p2}")
    print(f"Modulus n = p1 * p2: {n}")
    
    # Choose two coprime exponents
    e1 = 65537  # Common RSA exponent
    e2 = 17     # Another small exponent
    
    print(f"\nPublic exponents:")
    print(f"e1 = {e1}")
    print(f"e2 = {e2}")
    
    # Verify exponents are coprime
    phi = (p1 - 1) * (p2 - 1)
    gcd_e1_phi = math.gcd(e1, phi)
    gcd_e2_phi = math.gcd(e2, phi)
    gcd_e1_e2 = math.gcd(e1, e2)
    
    print(f"\nVerifying exponent properties:")
    print(f"gcd(e1, φ(n)) = {gcd_e1_phi}")
    print(f"gcd(e2, φ(n)) = {gcd_e2_phi}")
    print(f"gcd(e1, e2) = {gcd_e1_e2}")
    
    if gcd_e1_phi != 1 or gcd_e2_phi != 1:
        print("✗ ERROR: Exponents not coprime with φ(n)")
        return
    
    if gcd_e1_e2 != 1:
        print("✗ ERROR: Exponents not coprime with each other")
        return
    
    print("✓ All exponents are properly coprime")
    
    # Calculate private exponents (for verification only)
    d1 = inverse(e1, phi)
    d2 = inverse(e2, phi)
    
    print(f"\nPrivate exponents (for verification only):")
    print(f"d1 = {d1}")
    print(f"d2 = {d2}")
    
    # Create RSA key pairs
    rsa1_pub = (e1, n)
    rsa1_pri = (d1, n)
    rsa2_pub = (e2, n)
    rsa2_pri = (d2, n)
    
    print(f"\nRSA Key Pairs:")
    print(f"RSA1 Public:  (e={e1}, n={n})")
    print(f"RSA1 Private: (d={d1}, n={n})")
    print(f"RSA2 Public:  (e={e2}, n={n})")
    print(f"RSA2 Private: (d={d2}, n={n})")
    
    # Encrypt the same message with both keys
    plaintext = b'This is a secret message that will be recovered!'
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    
    print(f"\nOriginal message: {plaintext}")
    print(f"Message as integer: {plaintext_int}")
    
    # Encrypt with both exponents
    c1 = pow(plaintext_int, e1, n)
    c2 = pow(plaintext_int, e2, n)
    
    print(f"\nCiphertexts:")
    print(f"c1 = m^{e1} mod n = {c1}")
    print(f"c2 = m^{e2} mod n = {c2}")
    
    # Perform the common modulus attack
    print(f"\n=== Common Modulus Attack ===")
    print(f"Finding integers u, v such that u*{e1} + v*{e2} = 1")
    
    # Use extended GCD to find u and v
    gcd_result, u, v = extended_gcd(e1, e2)
    
    print(f"Extended GCD result: {gcd_result}")
    print(f"Coefficients: u = {u}, v = {v}")
    
    # Verify the Bézout identity
    bezout_check = u * e1 + v * e2
    print(f"Verification: {u} * {e1} + {v} * {e2} = {bezout_check}")
    
    if bezout_check != 1:
        print("✗ ERROR: Bézout identity verification failed")
        return
    
    print("✓ Bézout identity verified")
    
    # Recover the plaintext using the attack
    print(f"\nRecovering plaintext: m = c1^{u} * c2^{v} mod n")
    
    # Handle negative exponents
    if u < 0:
        c1_term = pow(inverse(c1, n), -u, n)
        print(f"c1^{u} = (c1^(-1))^{-u} mod n")
    else:
        c1_term = pow(c1, u, n)
        print(f"c1^{u} mod n")
    
    if v < 0:
        c2_term = pow(inverse(c2, n), -v, n)
        print(f"c2^{v} = (c2^(-1))^{-v} mod n")
    else:
        c2_term = pow(c2, v, n)
        print(f"c2^{v} mod n")
    
    # Calculate the final result
    recovered_int = (c1_term * c2_term) % n
    
    print(f"\nRecovered integer: {recovered_int}")
    
    # Convert back to bytes
    try:
        recovered_bytes = recovered_int.to_bytes((recovered_int.bit_length() + 7) // 8, byteorder='big')
        recovered_text = recovered_bytes.decode('utf-8')
        
        print(f"Recovered message: {recovered_bytes}")
        print(f"Recovered text: {recovered_text}")
        
        # Verify the attack succeeded
        if recovered_text == plaintext.decode('utf-8'):
            print("✓ SUCCESS: Common modulus attack recovered the original message!")
        else:
            print("✗ FAILED: Recovered message doesn't match original")
            
    except Exception as e:
        print(f"✗ ERROR: Could not convert recovered integer to text: {e}")

def main():
    """
    Main demonstration function.
    """
    print("Common Modulus Attack on RSA")
    print("=" * 60)
    
    # Demonstrate the attack
    demonstrate_common_modulus_attack()

if __name__ == '__main__':
    main()
