#!/usr/bin/env python3
"""
Common Prime Attack on RSA

This script demonstrates the catastrophic security failure that occurs when
two or more RSA moduli share a common prime factor. This attack uses the
Greatest Common Divisor (GCD) to efficiently factorize multiple RSA keys
that share common factors.

Mathematical Foundation:
If n1 = p * q1 and n2 = p * q2 (where p is shared), then:
- gcd(n1, n2) = p
- n1 / p = q1
- n2 / p = q2

Attack Process:
1. Collect multiple RSA moduli
2. Compute GCD between pairs of moduli
3. If GCD > 1, we found a common factor
4. Divide each modulus by the common factor to get the other factors
"""

from Crypto.Util.number import getPrime
from gmpy2 import gcd
import itertools

def demonstrate_common_prime_attack():
    """
    Demonstrate the common prime attack with multiple RSA moduli.
    
    This function generates RSA moduli that share common primes and
    shows how the GCD attack can quickly factorize all affected keys.
    """
    print("=== Common Prime Attack on RSA ===")
    print("This attack exploits RSA moduli that share common prime factors")
    
    # Generate primes for our demonstration
    print("\nGenerating test primes...")
    p1 = getPrime(1024)  # Shared prime - this is the vulnerability
    p2 = getPrime(1024)  # Unique prime for first modulus
    p3 = getPrime(1024)  # Unique prime for second modulus
    
    print(f"Shared prime p1: {p1}")
    print(f"Unique prime p2: {p2}")
    print(f"Unique prime p3: {p3}")
    
    # Create RSA moduli that share the common prime p1
    n1 = p1 * p2
    n2 = p1 * p3
    
    print(f"\nRSA moduli:")
    print(f"n1 = p1 * p2 = {n1}")
    print(f"n2 = p1 * p3 = {n2}")
    print(f"Both moduli share the common prime p1")
    
    # Perform the GCD attack
    print(f"\n=== GCD Attack ===")
    print(f"Computing gcd(n1, n2)...")
    
    # Calculate GCD - this should reveal the shared prime
    common_factor = gcd(n1, n2)
    
    print(f"gcd(n1, n2) = {common_factor}")
    
    # Verify we found the shared prime
    if common_factor == p1:
        print("✓ SUCCESS: Found the shared prime!")
        
        # Calculate the other factors
        factor1 = n1 // common_factor
        factor2 = n2 // common_factor
        
        print(f"\nFactorization results:")
        print(f"n1 = {common_factor} * {factor1}")
        print(f"n2 = {common_factor} * {factor2}")
        
        # Verify factorizations
        if common_factor * factor1 == n1 and common_factor * factor2 == n2:
            print("✓ VERIFIED: Both RSA moduli completely factorized!")
            
            # Check if we recovered the original primes
            if factor1 == p2 and factor2 == p3:
                print("✓ Original primes recovered - RSA keys completely broken!")
            else:
                print("⚠ Different factorization order - still breaks RSA security")
        else:
            print("✗ ERROR: Factorization verification failed")
    else:
        print("✗ FAILED: GCD attack did not reveal the expected shared prime")

def multiple_moduli_attack():
    """
    Demonstrate the attack with multiple RSA moduli.
    
    This shows how the attack scales when checking many RSA keys
    for common factors.
    """
    print("\n=== Multiple Moduli Attack ===")
    print("Demonstrating attack against multiple RSA keys")
    
    # Generate multiple primes
    primes = [getPrime(512) for _ in range(5)]
    
    print(f"Generated {len(primes)} primes for testing")
    
    # Create RSA moduli with some shared primes
    moduli = []
    moduli.append(primes[0] * primes[1])  # n1 = p0 * p1
    moduli.append(primes[0] * primes[2])  # n2 = p0 * p2 (shares p0 with n1)
    moduli.append(primes[1] * primes[3])  # n3 = p1 * p3 (shares p1 with n1)
    moduli.append(primes[2] * primes[4])  # n4 = p2 * p4 (shares p2 with n2)
    moduli.append(primes[3] * primes[4])  # n5 = p3 * p4 (shares p3 with n3, p4 with n4)
    
    print(f"Created {len(moduli)} RSA moduli with shared prime relationships")
    
    # Check all pairs for common factors
    print("\nChecking all pairs for common factors...")
    
    vulnerable_pairs = []
    
    for i, j in itertools.combinations(range(len(moduli)), 2):
        common_factor = gcd(moduli[i], moduli[j])
        
        if common_factor > 1:
            print(f"✓ VULNERABLE: moduli[{i}] and moduli[{j}] share factor {common_factor}")
            vulnerable_pairs.append((i, j, common_factor))
            
            # Factorize both moduli
            factor_i = moduli[i] // common_factor
            factor_j = moduli[j] // common_factor
            
            print(f"  n{i} = {common_factor} * {factor_i}")
            print(f"  n{j} = {common_factor} * {factor_j}")
        else:
            print(f"✓ SECURE: moduli[{i}] and moduli[{j}] share no common factors")
    
    print(f"\nAttack Summary:")
    print(f"- Total moduli checked: {len(moduli)}")
    print(f"- Vulnerable pairs found: {len(vulnerable_pairs)}")
    print(f"- Compromise rate: {len(vulnerable_pairs) / (len(moduli) * (len(moduli) - 1) // 2) * 100:.1f}%")

def main():
    """
    Main demonstration function.
    """
    print("Common Prime Attack on RSA")
    print("=" * 50)
    
    # Demonstrate basic attack
    demonstrate_common_prime_attack()
    
    # Show attack on multiple moduli
    multiple_moduli_attack()

if __name__ == '__main__':
    main()
