#!/usr/bin/env python3
"""
Random Key Generation - Cryptographically Secure Random Bytes

This script demonstrates how to generate cryptographically secure random bytes
using PyCryptodome's get_random_bytes function.
"""

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def generate_random_key(length=32):
    """Generate a cryptographically secure random key."""
    return get_random_bytes(length)


def generate_random_iv(block_size=16):
    """Generate a random initialization vector."""
    return get_random_bytes(block_size)


def main():
    """Demonstrate random key and IV generation."""
    print("=== Random Key Generation ===")
    
    # Generate a 40-byte random key for general cryptographic use
    random_key = generate_random_key(40)
    print(f"40-byte random key: {random_key.hex()}")
    
    # Generate a random IV equal to AES block size (16 bytes)
    random_iv = generate_random_iv(AES.block_size)
    print(f"AES IV ({AES.block_size} bytes): {random_iv.hex()}")
    
    # Generate keys for different AES variants
    print("\n=== AES Key Sizes ===")
    for key_size in AES.key_size:
        key = generate_random_key(key_size)
        print(f"AES-{key_size*8} key: {key.hex()}")

if __name__ == '__main__':
    main()
