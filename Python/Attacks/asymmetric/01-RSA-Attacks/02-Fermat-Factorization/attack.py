#!/usr/bin/env python3
"""
Fermat's Factorization Attack on RSA

This script demonstrates Fermat's factorization method, which is particularly
effective against RSA moduli where the prime factors are close to each other.
The attack exploits the mathematical relationship between close primes.

Mathematical Foundation:
If n = p * q where p and q are close, then:
- n ≈ p² (approximately a perfect square)
- We can find a, b such that n = a² - b² = (a+b)(a-b)
- Where a+b = p and a-b = q

Attack Process:
1. Start with a = ceil(√n)
2. Calculate b² = a² - n
3. If b² is a perfect square, we found the factors
4. Otherwise, increment a and repeat
"""

from gmpy2 import isqrt, next_prime
from Crypto.Util.number import getPrime, getRandomInteger
import math

def fermat_factorization(n, max_iterations=1000000):
    """
    Perform Fermat's factorization on integer n.
    
    This algorithm attempts to factor n by finding integers a and b such that
    n = a² - b² = (a+b)(a-b). It's most effective when the factors are close.
    
    Args:
        n (int): The integer to factor
        max_iterations (int): Maximum number of iterations to prevent infinite loops
        
    Returns:
        tuple: (p, q) where p and q are factors of n, or (None, None) if failed
    """
    print(f"Starting Fermat factorization of n = {n}")
    print(f"n has {n.bit_length()} bits")
    
    # Start with a = ceil(sqrt(n))
    a = isqrt(n)
    if a * a < n:
        a += 1
    
    print(f"Initial a = {a}")
    
    # Calculate initial b² = a² - n
    b_squared = a * a - n
    b = isqrt(b_squared)
    
    print(f"Initial b² = {b_squared}")
    print(f"Initial b = {b}")
    
    # Check if b² is a perfect square
    if b * b == b_squared:
        print("Found factors immediately!")
        p = a + b
        q = a - b
        return p, q
    
    print("Starting iteration process...")
    
    # Iterate until we find a perfect square
    for i in range(1, max_iterations):
        a += 1
        b_squared = a * a - n
        b = isqrt(b_squared)
        
        # Print progress for first few iterations and then sporadically
        if i <= 10 or i % 10000 == 0:
            print(f"Iteration {i}: a = {a}, b² = {b_squared}, b = {b}")
        
        # Check if b² is a perfect square
        if b * b == b_squared:
            print(f"✓ SUCCESS: Found factors at iteration {i}")
            p = a + b
            q = a - b
            
            # Verify the factorization
            if p * q == n:
                print(f"✓ VERIFIED: {p} * {q} = {p * q}")
                return p, q
            else:
                print("✗ ERROR: Factorization verification failed")
                return None, None
    
    print(f"✗ FAILED: Could not factor n within {max_iterations} iterations")
    return None, None

def generate_close_primes(base_bits, delta_bits):
    """
    Generate two primes that are close to each other for testing Fermat's method.
    
    Args:
        base_bits (int): Bit length for the base prime
        delta_bits (int): Maximum bit length for the difference between primes
        
    Returns:
        tuple: (p1, p2, delta) where p1 and p2 are close primes
    """
    print(f"Generating close primes with base ~{base_bits} bits, delta ~{delta_bits} bits")
    
    # Generate first prime
    p1 = getPrime(base_bits)
    
    # Generate a small delta
    delta = getRandomInteger(delta_bits)
    
    # Find the next prime after p1 + delta
    p2 = next_prime(p1 + delta)
    
    actual_delta = p2 - p1
    
    print(f"Prime p1: {p1}")
    print(f"Prime p2: {p2}")
    print(f"Delta (p2 - p1): {actual_delta}")
    print(f"Delta bit length: {actual_delta.bit_length()}")
    
    return p1, p2, actual_delta

def analyze_fermat_conditions(p1, p2):
    """
    Analyze why Fermat's method works well for given primes.
    
    Args:
        p1 (int): First prime
        p2 (int): Second prime
    """
    n = p1 * p2
    delta = abs(p2 - p1)
    
    print(f"\n=== Fermat's Method Analysis ===")
    print(f"n = p1 * p2 = {n}")
    print(f"√n ≈ {isqrt(n)}")
    print(f"(p1 + p2) / 2 = {(p1 + p2) // 2}")
    print(f"(p2 - p1) / 2 = {(p2 - p1) // 2}")
    
    # The closer the primes, the fewer iterations needed
    expected_iterations = (delta + 1) // 2
    print(f"Expected iterations: ~{expected_iterations}")
    
    # Ratio analysis
    ratio = p2 / p1 if p1 < p2 else p1 / p2
    print(f"Prime ratio: {ratio:.6f}")
    
    if ratio < 1.1:
        print("✓ Primes are very close - Fermat's method should be very fast")
    elif ratio < 2.0:
        print("⚠ Primes are moderately close - Fermat's method should work")
    else:
        print("✗ Primes are far apart - Fermat's method may be slow")

def demonstrate_fermat_attack():
    """
    Demonstrate Fermat's factorization attack with close primes.
    """
    print("=== Fermat's Factorization Attack ===")
    print("This attack is effective when RSA primes are close to each other")
    
    # Generate test case with close primes
    base_bits = 400  # Size of base prime
    delta_bits = 100  # Maximum size of difference
    
    p1, p2, delta = generate_close_primes(base_bits, delta_bits)
    
    # Analyze why this case is vulnerable
    analyze_fermat_conditions(p1, p2)
    
    # Create the RSA modulus
    n = p1 * p2
    
    print(f"\n=== Factorization Attack ===")
    print(f"Target modulus n = {n}")
    print(f"Modulus bit length: {n.bit_length()}")
    
    # Perform Fermat's factorization
    import time
    start_time = time.time()
    
    p, q = fermat_factorization(n)
    
    end_time = time.time()
    
    if p and q:
        print(f"\n✓ ATTACK SUCCESSFUL!")
        print(f"Recovered factors:")
        print(f"  p = {p}")
        print(f"  q = {q}")
        print(f"Attack time: {end_time - start_time:.6f} seconds")
        
        # Verify we recovered the original primes
        if (p == p1 and q == p2) or (p == p2 and q == p1):
            print("✓ Original primes recovered - RSA completely broken!")
        else:
            print("⚠ Different factorization found - still breaks RSA")
            
    else:
        print(f"\n✗ ATTACK FAILED!")
        print(f"Could not factor the modulus in reasonable time")

def main():
    """
    Main demonstration function.
    """
    print("Fermat's Factorization Attack on RSA")
    print("=" * 60)
    
    # Demonstrate the attack
    demonstrate_fermat_attack()

if __name__ == '__main__':
    main()
