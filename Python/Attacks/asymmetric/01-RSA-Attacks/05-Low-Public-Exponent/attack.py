#!/usr/bin/env python3
"""
Low Public Exponent Attack on RSA

This script demonstrates the low public exponent attack against RSA.
When a small public exponent (like e=3) is used and the message is
small enough, the ciphertext may be smaller than the modulus, allowing
direct root extraction to recover the plaintext.

Mathematical Foundation:
If m^e < n, then:
- c = m^e mod n = m^e (no modular reduction occurs)
- m = ∛c (for e=3, just take the cube root)

Attack Conditions:
1. Small public exponent (e=3, e=5, etc.)
2. Small message (m^e < n)
3. No proper padding scheme
"""

from Crypto.PublicKey import RSA
import math

def integer_nth_root(n, k):
    """
    Calculate the integer nth root of k.
    
    This function computes the largest integer r such that r^n <= k.
    Uses binary search for efficiency and accuracy.
    
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

def demonstrate_low_exponent_attack():
    """
    Demonstrate the low public exponent attack on RSA.
    
    This function creates an RSA key with a small exponent (e=3)
    and shows how small messages can be recovered by taking roots.
    """
    print("=== Low Public Exponent Attack on RSA ===")
    print("This attack exploits small public exponents with unpadded messages")
    
    # Generate RSA key with small exponent
    print("\nGenerating RSA key with small exponent (e=3)...")
    
    try:
        rsa_keypair = RSA.generate(2048, e=3)
        e = rsa_keypair.e
        n = rsa_keypair.n
        
        print(f"✓ RSA key generated successfully")
        print(f"Public exponent e: {e}")
        print(f"Modulus n: {n}")
        print(f"Modulus bit length: {n.bit_length()}")
        
    except Exception as error:
        print(f"✗ Error generating RSA key: {error}")
        return
    
    # Test with a small message
    print(f"\n=== Testing with Small Message ===")
    
    # Use a relatively small message
    message = b'This message needs to be encrypted'
    message_int = int.from_bytes(message, byteorder='big')
    
    print(f"Original message: {message}")
    print(f"Message as integer: {message_int}")
    print(f"Message bit length: {message_int.bit_length()}")
    
    # Calculate m^e to see if it's less than n
    message_cubed = message_int ** e
    print(f"Message^{e}: {message_cubed}")
    print(f"Message^{e} bit length: {message_cubed.bit_length()}")
    
    # Check if message^e < n
    if message_cubed < n:
        print(f"✓ VULNERABLE: m^{e} < n, attack will succeed")
        vulnerable = True
    else:
        print(f"✗ NOT VULNERABLE: m^{e} >= n, attack will fail")
        vulnerable = False
    
    # Encrypt the message
    print(f"\nEncrypting message...")
    ciphertext = pow(message_int, e, n)
    
    print(f"Ciphertext c = m^{e} mod n: {ciphertext}")
    print(f"Ciphertext bit length: {ciphertext.bit_length()}")
    
    # Perform the attack
    print(f"\n=== Low Exponent Attack ===")
    
    if vulnerable:
        print(f"Since m^{e} < n, the ciphertext is just m^{e}")
        print(f"We can recover m by taking the {e}th root of c")
        
        # Calculate the eth root
        print(f"Calculating {e}th root of ciphertext...")
        
        recovered_int = integer_nth_root(e, ciphertext)
        
        print(f"Recovered integer: {recovered_int}")
        
        # Convert back to bytes
        try:
            recovered_bytes = recovered_int.to_bytes((recovered_int.bit_length() + 7) // 8, byteorder='big')
            recovered_text = recovered_bytes.decode('utf-8')
            
            print(f"Recovered message: {recovered_bytes}")
            print(f"Recovered text: {recovered_text}")
            
            # Verify the attack succeeded
            if recovered_text == message.decode('utf-8'):
                print("✓ SUCCESS: Low exponent attack recovered the original message!")
            else:
                print("✗ FAILED: Recovered message doesn't match original")
                
        except Exception as e:
            print(f"✗ ERROR: Could not convert recovered integer to text: {e}")
    
    else:
        print(f"Attack cannot proceed because m^{e} >= n")
        print(f"The modular reduction prevents direct root extraction")
        
        # Try the attack anyway to show it fails
        print(f"\nTrying attack anyway (will fail)...")
        failed_recovery = integer_nth_root(e, ciphertext)
        
        try:
            failed_bytes = failed_recovery.to_bytes((failed_recovery.bit_length() + 7) // 8, byteorder='big')
            failed_text = failed_bytes.decode('utf-8', errors='replace')
            print(f"Failed recovery attempt: {failed_text}")
        except:
            print(f"Failed recovery attempt: {failed_recovery}")
        
        print("✗ Attack failed as expected")

def main():
    """
    Main demonstration function.
    """
    print("Low Public Exponent Attack on RSA")
    print("=" * 60)
    
    # Demonstrate the attack
    demonstrate_low_exponent_attack()

if __name__ == '__main__':
    main()
