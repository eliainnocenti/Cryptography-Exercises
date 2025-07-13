#!/usr/bin/env python3
"""
AES Block Cipher with Padding - CBC Mode Encryption

This script demonstrates AES encryption in CBC mode with proper padding handling
for both aligned and unaligned data.
"""

import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_aes_cbc(data, key, iv):
    """Encrypt data using AES-CBC mode with automatic padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    return cipher.encrypt(padded_data)

def decrypt_aes_cbc(ciphertext, key, iv):
    """Decrypt data using AES-CBC mode and remove padding."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

def main():
    """Demonstrate AES encryption with and without padding."""
    print("=== AES Block Cipher with Padding ===")
    
    # Display available AES key sizes
    print(f"Available AES key sizes: {AES.key_size} bytes")
    print(f"AES block size: {AES.block_size} bytes")
    
    # Generate cryptographic material
    key = get_random_bytes(AES.key_size[2])  # 256-bit key
    iv = get_random_bytes(AES.block_size)    # 16-byte IV
    
    print(f"\nGenerated AES-256 key: {key.hex()}")
    print(f"Generated IV: {iv.hex()}")
    
    # Test 1: Encrypt aligned data (no padding needed)
    print("\n=== Test 1: Aligned Data (32 bytes) ===")
    aligned_data = b'These data are to be encrypted!!'
    print(f"Original data length: {len(aligned_data)} bytes")
    print(f"Original data: {aligned_data}")
    
    # Encrypt without explicit padding (data is already aligned)
    cipher_enc = AES.new(key, AES.MODE_CBC, iv)
    ciphertext_aligned = cipher_enc.encrypt(aligned_data)
    print(f"Ciphertext length: {len(ciphertext_aligned)} bytes")
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext_aligned).decode()}")
    
    # Decrypt
    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    plaintext_aligned = cipher_dec.decrypt(ciphertext_aligned)
    print(f"Decrypted: {plaintext_aligned}")
    
    # Test 2: Encrypt unaligned data (padding required)
    print("\n=== Test 2: Unaligned Data (24 bytes) ===")
    unaligned_data = b'Unaligned data to cipher'
    print(f"Original data length: {len(unaligned_data)} bytes")
    print(f"Original data: {unaligned_data}")
    
    # Encrypt with explicit padding
    padded_data = pad(unaligned_data, AES.block_size)
    print(f"Padded data: {padded_data}")
    print(f"Padded data length: {len(padded_data)} bytes")
    
    cipher_enc = AES.new(key, AES.MODE_CBC, iv)
    ciphertext_unaligned = cipher_enc.encrypt(padded_data)
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext_unaligned).decode()}")
    
    # Decrypt and remove padding
    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher_dec.decrypt(ciphertext_unaligned)
    print(f"Decrypted (with padding): {decrypted_padded}")
    
    plaintext_unaligned = unpad(decrypted_padded, AES.block_size)
    print(f"Decrypted (padding removed): {plaintext_unaligned.decode('utf-8')}")
    
    # Verify data integrity
    assert unaligned_data == plaintext_unaligned, "Data integrity check failed!"
    print("✓ Data integrity verified!")
    
    # Test 3: Using convenience functions
    print("\n=== Test 3: Using Convenience Functions ===")
    test_data = b'Test message for encryption'
    
    # Encrypt using convenience function
    ciphertext = encrypt_aes_cbc(test_data, key, iv)
    print(f"Encrypted: {base64.b64encode(ciphertext).decode()}")
    
    # Decrypt using convenience function
    decrypted = decrypt_aes_cbc(ciphertext, key, iv)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    
    assert test_data == decrypted, "Convenience function test failed!"
    print("✓ Convenience functions work correctly!")

if __name__ == '__main__':
    main()
