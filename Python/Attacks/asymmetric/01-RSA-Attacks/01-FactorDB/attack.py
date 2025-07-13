#!/usr/bin/env python3
"""
FactorDB Attack on RSA

This script demonstrates how to use the FactorDB online database to factorize
RSA moduli. FactorDB is a web service that maintains a database of integer
factorizations and can quickly factor numbers that have been previously
computed or have known factorization patterns.

Attack Overview:
1. Generate an RSA modulus n = p * q
2. Query FactorDB to attempt factorization
3. If factors are found, the RSA key is completely broken
"""

from Crypto.Util.number import getPrime
from factordb.factordb import FactorDB

def demonstrate_factordb_attack():
    """
    Demonstrate a FactorDB attack on a small RSA modulus.
    
    This function generates a small RSA modulus and attempts to factor it
    using the FactorDB service. Small moduli are used for demonstration
    purposes as they are more likely to be in the database.
    """
    print("=== FactorDB Attack on RSA ===")
    print("This attack uses an online database to find known factorizations")
    
    # Generate small primes for demonstration (150 bits each)
    # In practice, RSA uses much larger primes (1024+ bits each)
    n_length = 150
    
    print(f"Generating two {n_length}-bit primes...")
    p1 = getPrime(n_length)
    p2 = getPrime(n_length)
    
    print(f"Prime p1: {p1}")
    print(f"Prime p2: {p2}")
    
    # Create RSA modulus
    n = p1 * p2
    print(f"RSA modulus n = p1 * p2: {n}")
    print(f"Modulus bit length: {n.bit_length()}")
    
    # Attempt to factor using FactorDB
    print("\nQuerying FactorDB for factorization...")
    
    try:
        # Create FactorDB object and query the database
        f = FactorDB(n)
        f.connect()
        
        # Get the factorization
        factors = f.get_factor_list()
        
        print(f"FactorDB result: {factors}")
        
        # Analyze the results
        if len(factors) == 2 and factors[0] * factors[1] == n:
            print("✓ SUCCESS: RSA modulus successfully factored!")
            print(f"  Factor 1: {factors[0]}")
            print(f"  Factor 2: {factors[1]}")
            print(f"  Verification: {factors[0]} * {factors[1]} = {factors[0] * factors[1]}")
            
            # Check if we recovered the original primes
            if (factors[0] == p1 and factors[1] == p2) or (factors[0] == p2 and factors[1] == p1):
                print("✓ Original primes recovered - RSA key completely broken!")
            else:
                print("⚠ Different factorization found - still breaks RSA security")
                
        else:
            print("✗ FAILED: Could not factor the modulus")
            print("  This could mean:")
            print("  - The modulus is not in FactorDB's database")
            print("  - The modulus is too large for current factorization methods")
            print("  - Network connectivity issues")
            
    except Exception as e:
        print(f"✗ ERROR: Failed to query FactorDB: {e}")
        print("  This might be due to:")
        print("  - Network connectivity issues")
        print("  - FactorDB service unavailable")
        print("  - Missing factordb-python library")

def main():
    """
    Main demonstration function.
    """
    print("RSA FactorDB Attack Demonstration")
    print("=" * 50)
    
    # Demonstrate the attack
    demonstrate_factordb_attack()

if __name__ == '__main__':
    main()
