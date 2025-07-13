#!/usr/bin/env python3
"""
ChaCha20 Stream Cipher - Fast and Secure Stream Encryption

This script demonstrates ChaCha20 stream cipher encryption with automatic
and manual nonce generation.
"""

import base64
import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20

def encrypt_chacha20(plaintext, key=None, nonce=None):
    """Encrypt data using ChaCha20 stream cipher."""
    if key is None:
        key = get_random_bytes(ChaCha20.key_size)
    
    if nonce is None:
        cipher = ChaCha20.new(key=key)
    else:
        cipher = ChaCha20.new(key=key, nonce=nonce)
    
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, cipher.nonce, key

def decrypt_chacha20(ciphertext, key, nonce):
    """Decrypt data using ChaCha20 stream cipher."""
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

def main():
    """Demonstrate ChaCha20 stream cipher encryption."""
    print("=== ChaCha20 Stream Cipher ===")
    
    # Define test message
    plaintext = b'This is the secret message to encrypt'
    print(f"Original message: {plaintext.decode('utf-8')}")
    print(f"Message length: {len(plaintext)} bytes")
    
    # Test 1: Automatic nonce generation
    print("\n=== Test 1: Automatic Nonce Generation ===")
    key = get_random_bytes(ChaCha20.key_size)
    print(f"Generated key: {key.hex()}")
    
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)
    
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode()}")
    print(f"Nonce (base64): {base64.b64encode(cipher.nonce).decode()}")
    print(f"Nonce length: {len(cipher.nonce)} bytes")
    
    # Verify that ciphertext and plaintext have the same length
    print(f"Plaintext memory size: {sys.getsizeof(plaintext)} bytes")
    print(f"Ciphertext memory size: {sys.getsizeof(ciphertext)} bytes")
    print(f"Length comparison: {len(plaintext)} == {len(ciphertext)} -> {len(plaintext) == len(ciphertext)}")
    
    # Test 2: Manual nonce generation
    print("\n=== Test 2: Manual Nonce Generation ===")
    manual_nonce = get_random_bytes(12)  # ChaCha20 uses 12-byte nonces
    print(f"Manual nonce: {manual_nonce.hex()}")
    
    cipher_manual = ChaCha20.new(key=key, nonce=manual_nonce)
    ciphertext_manual = cipher_manual.encrypt(plaintext)
    
    print(f"Ciphertext (base64): {base64.b64encode(ciphertext_manual).decode()}")
    
    # Test 3: Using convenience functions
    print("\n=== Test 3: Using Convenience Functions ===")
    test_message = b'Testing convenience functions'
    
    # Encrypt
    encrypted_data, used_nonce, used_key = encrypt_chacha20(test_message)
    print(f"Encrypted: {base64.b64encode(encrypted_data).decode()}")
    
    # Decrypt
    decrypted_data = decrypt_chacha20(encrypted_data, used_key, used_nonce)
    print(f"Decrypted: {decrypted_data.decode('utf-8')}")
    
    # Verify
    assert test_message == decrypted_data, "Decryption failed!"
    print("✓ Encryption/decryption successful!")
    
    # Test 4: Stream cipher properties
    print("\n=== Test 4: Stream Cipher Properties ===")
    
    # Demonstrate that different plaintexts with same key/nonce produce different ciphertexts
    plaintext1 = b'Message one'
    plaintext2 = b'Message two'
    
    cipher1 = ChaCha20.new(key=key)
    cipher2 = ChaCha20.new(key=key, nonce=cipher1.nonce)
    
    ct1 = cipher1.encrypt(plaintext1)
    ct2 = cipher2.encrypt(plaintext2)
    
    print(f"Same key/nonce, different plaintexts:")
    print(f"CT1: {ct1.hex()}")
    print(f"CT2: {ct2.hex()}")
    print(f"Different ciphertexts: {ct1 != ct2}")

if __name__ == '__main__':
    main()
