#!/usr/bin/env python3
"""
Ciphertext Generation Helper for CBC Padding Oracle Attack

This utility generates ciphertexts for testing the CBC padding oracle attack.
It encrypts a sample message using AES-CBC and outputs the necessary data
for the attack demonstration.

Purpose:
- Creates test data for padding oracle attacks
- Demonstrates proper encryption before showing the attack
- Helps set up the vulnerable scenario for educational purposes

Security Note:
This tool is for educational demonstration only. In real scenarios,
the attacker would not have access to the encryption key or the ability
to generate arbitrary ciphertexts.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Import the secret key and IV from the parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mysecrets import cbc_oracle_key as key
from mydata import cbc_oracle_iv as iv


def generate_test_ciphertext():
    """
    Generate a test ciphertext for the padding oracle attack demonstration.
    
    This function:
    1. Takes a sample message (often a flag or challenge text)
    2. Encrypts it using AES-CBC with a known key and IV
    3. Outputs the ciphertext and verification data
    
    Returns:
        bytes: The encrypted ciphertext
    """
    # Initialize AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Sample message - typically a flag or challenge text
    # This represents the secret data that the attacker wants to decrypt
    msg = b'03LPYOV{How_many_nice_things_can_you_find_1_bit_at_the_time?}'
    
    print("=== Ciphertext Generation for CBC Padding Oracle Attack ===")
    print(f"Original message: {msg}")
    print(f"Message length: {len(msg)} bytes")
    print(f"IV (hex): {iv.hex()}")
    print(f"Key (hex): {key.hex()}")
    
    # Encrypt the message with PKCS#7 padding
    ciphertext = cipher.encrypt(pad(msg, AES.block_size))
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Number of blocks: {len(ciphertext) // AES.block_size}")
    
    # Verify the encryption by decrypting (for testing purposes)
    print("\n=== Verification ===")
    verification_cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = verification_cipher.decrypt(ciphertext)
    print(f"Decrypted (with padding): {decrypted}")
    
    # Show the block structure
    print(f"\n=== Block Structure ===")
    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i:i+AES.block_size]
        print(f"Block {i//AES.block_size}: {block.hex()}")
    
    print(f"\n=== Attack Setup ===")
    print("The attacker now has:")
    print("1. The ciphertext (obtained through interception)")
    print("2. The IV (often transmitted with the ciphertext)")
    print("3. Access to the padding oracle (the vulnerable server)")
    print("4. NO knowledge of the encryption key")
    print("\nThe goal is to decrypt the ciphertext using only the padding oracle!")
    
    return ciphertext


def main():
    """
    Main function to generate test ciphertext and display attack setup information.
    """
    ciphertext = generate_test_ciphertext()
    
    print(f"\n=== Generated Data for Attack ===")
    print("Copy this data to mydata.py:")
    print(f"cbc_oracle_ciphertext = {ciphertext}")
    
    print(f"\n=== Next Steps ===")
    print("1. Update mydata.py with the generated ciphertext")
    print("2. Start the CBC padding oracle server")
    print("3. Run the attack script to decrypt the message")
    print("4. Observe how the attack recovers the plaintext byte by byte")


if __name__ == '__main__':
    main()
