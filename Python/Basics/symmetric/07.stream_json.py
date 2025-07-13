"""
ChaCha20 encryption with JSON serialization for data storage and transmission.
Demonstrates practical data packaging for encrypted communications.
"""

import base64
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20

def encrypt_with_json_packaging(plaintext, key=None):
    """Encrypt data and package in JSON format.
    
    Args:
        plaintext (bytes): Data to encrypt
        key (bytes): ChaCha20 key (32 bytes), generates random if None
    
    Returns:
        str: JSON string containing nonce and ciphertext
    """
    # Generate key if not provided
    if key is None:
        key = get_random_bytes(32)
    
    # Generate random nonce
    nonce = get_random_bytes(12)
    
    # Create cipher and encrypt
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    
    # Encode to Base64 and package in JSON
    json_data = {
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    
    return json.dumps(json_data), key

def decrypt_from_json_package(json_string, key):
    """Decrypt data from JSON package.
    
    Args:
        json_string (str): JSON containing nonce and ciphertext
        key (bytes): ChaCha20 key used for encryption
    
    Returns:
        bytes: Decrypted plaintext
    """
    # Parse JSON and decode Base64
    data = json.loads(json_string)
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    
    # Create cipher and decrypt
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    
    return plaintext

def efficient_json_packaging(data_dict):
    """Demonstrate efficient JSON packaging using list comprehension.
    
    Args:
        data_dict (dict): Dictionary with bytes values to encode
    
    Returns:
        str: JSON string with Base64-encoded values
    """
    # Efficient encoding using dictionary comprehension
    json_keys = list(data_dict.keys())
    json_values = [base64.b64encode(data_dict[k]).decode() for k in json_keys]
    result = json.dumps(dict(zip(json_keys, json_values)))
    
    return result

def main():
    """Demonstrate ChaCha20 encryption with JSON packaging."""
    print("=== ChaCha20 with JSON Packaging Demo ===")
    
    # Original message
    plaintext = b'This is the secret message to encrypt'
    print(f"Original message: {plaintext}")
    
    # === Basic JSON Packaging ===
    print("\n=== Basic JSON Packaging ===")
    json_package, key = encrypt_with_json_packaging(plaintext)
    print(f"JSON package: {json_package}")
    
    # Decrypt from JSON package
    decrypted = decrypt_from_json_package(json_package, key)
    print(f"Decrypted message: {decrypted}")
    
    # Verify decryption
    assert plaintext == decrypted, "Decryption failed!"
    print("✓ Basic JSON packaging successful")
    
    # === Efficient JSON Packaging Demo ===
    print("\n=== Efficient JSON Packaging Demo ===")
    
    # Create cipher for efficient demo
    key2 = get_random_bytes(32)
    nonce2 = get_random_bytes(12)
    cipher2 = ChaCha20.new(key=key2, nonce=nonce2)
    ciphertext2 = cipher2.encrypt(plaintext)
    
    # Package using efficient method
    data_to_package = {
        'nonce': cipher2.nonce,
        'ciphertext': ciphertext2
    }
    
    efficient_json = efficient_json_packaging(data_to_package)
    print(f"Efficient JSON package: {efficient_json}")
    
    # Decrypt using the efficient package
    efficient_data = json.loads(efficient_json)
    decoded_data = {k: base64.b64decode(efficient_data[k]) for k in efficient_data.keys()}
    
    cipher_dec = ChaCha20.new(key=key2, nonce=decoded_data['nonce'])
    final_plaintext = cipher_dec.decrypt(decoded_data['ciphertext'])
    
    print(f"Final decrypted message: {final_plaintext}")
    
    # Verify final decryption
    assert plaintext == final_plaintext, "Efficient decryption failed!"
    print("✓ Efficient JSON packaging successful")

if __name__ == "__main__":
    main()
