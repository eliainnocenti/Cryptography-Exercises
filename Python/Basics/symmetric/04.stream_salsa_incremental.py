#!/usr/bin/env python3
"""
Salsa20 Stream Cipher - Incremental Encryption

This script demonstrates Salsa20 stream cipher with incremental encryption,
showing how stream ciphers can process data in chunks.
"""

from Crypto.Cipher import Salsa20
from Crypto.Random import get_random_bytes

def encrypt_salsa20_incremental(parts, key=None, nonce=None):
    """Encrypt multiple message parts incrementally using Salsa20."""
    if key is None:
        key = get_random_bytes(16)  # 128-bit key
    
    if nonce is None:
        cipher = Salsa20.new(key)
    else:
        cipher = Salsa20.new(key, nonce)
    
    ciphertext = b''
    for part in parts:
        ciphertext += cipher.encrypt(part)
    
    return ciphertext, cipher.nonce, key

def decrypt_salsa20(ciphertext, key, nonce):
    """Decrypt data using Salsa20 stream cipher."""
    cipher = Salsa20.new(key, nonce)
    return cipher.decrypt(ciphertext)

def main():
    """Demonstrate Salsa20 incremental encryption."""
    print("=== Salsa20 Stream Cipher - Incremental Encryption ===")
    
    # Test 1: Basic incremental encryption
    print("\n=== Test 1: Basic Incremental Encryption ===")
    
    # Use a fixed key for demonstration
    key = b'deadbeefdeadbeef'  # 128-bit key
    print(f"Key: {key.hex()}")
    
    # Create cipher with automatic nonce generation
    cipher = Salsa20.new(key)
    nonce = cipher.nonce
    print(f"Generated nonce: {nonce.hex()}")
    
    # Encrypt message parts incrementally
    part1 = b'The first part of the secret message. '
    part2 = b'The second part of the message.'
    
    print(f"Part 1: {part1.decode('utf-8')}")
    print(f"Part 2: {part2.decode('utf-8')}")
    
    ciphertext = cipher.encrypt(part1)
    ciphertext += cipher.encrypt(part2)
    
    print(f"Combined ciphertext: {ciphertext.hex()}")
    
    # Decrypt the complete ciphertext
    cipher_dec = Salsa20.new(key, nonce)
    plaintext = cipher_dec.decrypt(ciphertext)
    
    print(f"Decrypted message: {plaintext.decode('utf-8')}")
    
    # Test 2: Using convenience function
    print("\n=== Test 2: Using Convenience Function ===")
    
    message_parts = [
        b'First chunk of data. ',
        b'Second chunk of data. ',
        b'Final chunk of data.'
    ]
    
    print("Message parts:")
    for i, part in enumerate(message_parts, 1):
        print(f"  Part {i}: {part.decode('utf-8')}")
    
    # Encrypt incrementally
    encrypted_data, used_nonce, used_key = encrypt_salsa20_incremental(message_parts)
    print(f"Encrypted: {encrypted_data.hex()}")
    print(f"Used nonce: {used_nonce.hex()}")
    
    # Decrypt
    decrypted_data = decrypt_salsa20(encrypted_data, used_key, used_nonce)
    print(f"Decrypted: {decrypted_data.decode('utf-8')}")
    
    # Verify
    original_message = b''.join(message_parts)
    assert original_message == decrypted_data, "Decryption failed!"
    print("✓ Incremental encryption/decryption successful!")
    
    # Test 3: Stream cipher properties demonstration
    print("\n=== Test 3: Stream Cipher Properties ===")
    
    # Show that the same position in the keystream produces the same XOR
    test_key = get_random_bytes(16)
    test_nonce = get_random_bytes(8)
    
    # Encrypt the same plaintext at the same position
    cipher1 = Salsa20.new(test_key, test_nonce)
    cipher2 = Salsa20.new(test_key, test_nonce)
    
    test_plaintext = b'AAAA'  # Simple pattern
    ct1 = cipher1.encrypt(test_plaintext)
    ct2 = cipher2.encrypt(test_plaintext)
    
    print(f"Same key/nonce, same plaintext:")
    print(f"CT1: {ct1.hex()}")
    print(f"CT2: {ct2.hex()}")
    print(f"Identical ciphertexts: {ct1 == ct2}")
    
    # Show incremental vs batch encryption produces same result
    print("\n=== Test 4: Incremental vs Batch Encryption ===")
    
    full_message = b'This is a complete message for testing.'
    
    # Batch encryption
    cipher_batch = Salsa20.new(test_key, test_nonce)
    ct_batch = cipher_batch.encrypt(full_message)
    
    # Incremental encryption
    cipher_inc = Salsa20.new(test_key, test_nonce)
    ct_inc = cipher_inc.encrypt(full_message[:10])
    ct_inc += cipher_inc.encrypt(full_message[10:20])
    ct_inc += cipher_inc.encrypt(full_message[20:])
    
    print(f"Batch encryption:      {ct_batch.hex()}")
    print(f"Incremental encryption: {ct_inc.hex()}")
    print(f"Results identical: {ct_batch == ct_inc}")

if __name__ == '__main__':
    main()
