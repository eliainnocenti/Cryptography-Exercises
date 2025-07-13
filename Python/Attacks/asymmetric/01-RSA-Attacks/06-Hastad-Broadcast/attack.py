#!/usr/bin/env python3
"""
Håstad's Broadcast Attack on RSA

This script demonstrates Håstad's broadcast attack, which exploits RSA
systems that use the same small public exponent (typically e=3) to
encrypt the same message to multiple recipients with different moduli.

Mathematical Foundation:
Given:
- Same message m encrypted to e different recipients
- e different moduli n1, n2, ..., ne (pairwise coprime)
- Same public exponent e
- Ciphertexts c1, c2, ..., ce where ci = m^e mod ni

Using the Chinese Remainder Theorem:
- We can find x such that x ≡ ci (mod ni) for all i
- If all ni are pairwise coprime, then x = m^e mod (n1*n2*...*ne)
- If m^e < n1*n2*...*ne, then x = m^e exactly
- Therefore, m = ∛x (for e=3)
"""

from Crypto.PublicKey import RSA
import math

def integer_nth_root(n, k):
    """
    Calculate the integer nth root of k using binary search.
    
    Args:
        n (int): The root degree
        k (int): The number to find the root of
        
    Returns:
        int: The integer nth root of k
    """
    if k == 0:
        return 0
    if k == 1:
        return 1
    
    # Binary search for the nth root
    low = 0
    high = k
    
    while low <= high:
        mid = (low + high) // 2
        mid_n = mid ** n
        
        if mid_n == k:
            return mid
        elif mid_n < k:
            low = mid + 1
        else:
            high = mid - 1
    
    return high

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    
    Returns (gcd, x, y) such that ax + by = gcd(a, b).
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, y, x = extended_gcd(b % a, a)
        return (gcd, x - (b // a) * y, y)

def chinese_remainder_theorem(remainders, moduli):
    """
    Solve a system of congruences using the Chinese Remainder Theorem.
    
    Args:
        remainders (list): List of remainders [r1, r2, ..., rk]
        moduli (list): List of moduli [n1, n2, ..., nk]
        
    Returns:
        int: The solution x such that x ≡ ri (mod ni) for all i
    """
    if len(remainders) != len(moduli):
        raise ValueError("Number of remainders must equal number of moduli")
    
    # Calculate the product of all moduli
    N = 1
    for ni in moduli:
        N *= ni
    
    # Apply CRT formula
    x = 0
    for i in range(len(remainders)):
        ri = remainders[i]
        ni = moduli[i]
        Ni = N // ni
        
        # Find the modular inverse of Ni modulo ni
        gcd, Mi, _ = extended_gcd(Ni, ni)
        if gcd != 1:
            raise ValueError(f"Moduli are not pairwise coprime: gcd({Ni}, {ni}) = {gcd}")
        
        # Add this term to the solution
        x += ri * Ni * Mi
    
    return x % N

def demonstrate_hastad_broadcast_attack():
    """
    Demonstrate Håstad's broadcast attack on RSA.
    
    This function creates multiple RSA keys with the same small exponent,
    encrypts the same message to all recipients, and shows how to recover
    the plaintext using the Chinese Remainder Theorem.
    """
    print("=== Håstad's Broadcast Attack on RSA ===")
    print("This attack exploits broadcasting the same message with small exponents")
    
    # Attack parameters
    n_length = 1024
    e = 3  # Small public exponent
    
    print(f"\nAttack setup:")
    print(f"- Message encrypted to {e} different recipients")
    print(f"- All recipients use public exponent e = {e}")
    print(f"- Each recipient has a different {n_length}-bit modulus")
    
    # Generate RSA keys for multiple recipients
    print(f"\nGenerating RSA keys for {e} recipients...")
    
    rsa_keys = []
    moduli = []
    
    for i in range(e):
        print(f"Generating RSA key {i+1}...")
        rsa_key = RSA.generate(n_length, e=e)
        rsa_keys.append(rsa_key)
        moduli.append(rsa_key.n)
        
        print(f"  Recipient {i+1}: n{i+1} = {rsa_key.n}")
    
    print(f"✓ Generated {len(rsa_keys)} RSA keys")
    
    # Verify moduli are pairwise coprime
    print(f"\nVerifying moduli are pairwise coprime...")
    for i in range(len(moduli)):
        for j in range(i+1, len(moduli)):
            gcd = math.gcd(moduli[i], moduli[j])
            if gcd != 1:
                print(f"✗ ERROR: n{i+1} and n{j+1} are not coprime (gcd = {gcd})")
                return
    
    print("✓ All moduli are pairwise coprime")
    
    # Prepare the message
    message = b'This is the secret message to decrypt'
    message_int = int.from_bytes(message, byteorder='big')
    
    print(f"\nOriginal message: {message}")
    print(f"Message as integer: {message_int}")
    print(f"Message bit length: {message_int.bit_length()}")
    
    # Encrypt the message to all recipients
    print(f"\nEncrypting message to all {e} recipients...")
    
    ciphertexts = []
    for i, rsa_key in enumerate(rsa_keys):
        ciphertext = pow(message_int, e, rsa_key.n)
        ciphertexts.append(ciphertext)
        print(f"c{i+1} = m^{e} mod n{i+1} = {ciphertext}")
    
    # Check if direct cube root attack would work on individual ciphertexts
    print(f"\nChecking if individual direct attacks would work...")
    for i, (ciphertext, modulus) in enumerate(zip(ciphertexts, moduli)):
        message_cubed = message_int ** e
        if message_cubed < modulus:
            print(f"⚠ Individual attack possible on recipient {i+1}: m^{e} < n{i+1}")
        else:
            print(f"✓ Individual attack not possible on recipient {i+1}: m^{e} >= n{i+1}")
    
    # Check if Håstad attack conditions are met
    product_of_moduli = 1
    for modulus in moduli:
        product_of_moduli *= modulus
    
    message_cubed = message_int ** e
    
    print(f"\nHåstad attack conditions:")
    print(f"Product of all moduli: {product_of_moduli}")
    print(f"Message^{e}: {message_cubed}")
    
    if message_cubed < product_of_moduli:
        print(f"✓ VULNERABLE: m^{e} < n1*n2*n3, attack will succeed")
        attack_possible = True
    else:
        print(f"✗ NOT VULNERABLE: m^{e} >= n1*n2*n3, attack will fail")
        attack_possible = False
    
    # Perform Håstad's broadcast attack
    print(f"\n=== Håstad's Broadcast Attack ===")
    
    if attack_possible:
        print("Using Chinese Remainder Theorem to combine ciphertexts...")
        
        # Apply Chinese Remainder Theorem
        try:
            combined_result = chinese_remainder_theorem(ciphertexts, moduli)
            print(f"CRT result: {combined_result}")
            
            # Since m^e < n1*n2*n3, the CRT result equals m^e exactly
            print(f"Since m^{e} < n1*n2*n3, CRT result = m^{e} exactly")
            
            # Take the e-th root to recover the message
            print(f"Taking {e}th root to recover message...")
            recovered_int = integer_nth_root(e, combined_result)
            
            print(f"Recovered integer: {recovered_int}")
            
            # Convert back to bytes
            try:
                recovered_bytes = recovered_int.to_bytes((recovered_int.bit_length() + 7) // 8, byteorder='big')
                recovered_text = recovered_bytes.decode('utf-8')
                
                print(f"Recovered message: {recovered_bytes}")
                print(f"Recovered text: {recovered_text}")
                
                # Verify the attack succeeded
                if recovered_text == message.decode('utf-8'):
                    print("✓ SUCCESS: Håstad's broadcast attack recovered the original message!")
                else:
                    print("✗ FAILED: Recovered message doesn't match original")
                    
            except Exception as e:
                print(f"✗ ERROR: Could not convert recovered integer to text: {e}")
                
        except Exception as e:
            print(f"✗ ERROR: Chinese Remainder Theorem failed: {e}")
    
    else:
        print("Attack cannot proceed due to insufficient conditions")
        print("This could happen if:")
        print("1. Message is too large relative to moduli")
        print("2. Not enough ciphertexts available")
        print("3. Moduli are not pairwise coprime")

def main():
    """
    Main demonstration function.
    """
    print("Håstad's Broadcast Attack on RSA")
    print("=" * 60)
    
    # Demonstrate the attack
    demonstrate_hastad_broadcast_attack()
    
if __name__ == '__main__':
    main()
