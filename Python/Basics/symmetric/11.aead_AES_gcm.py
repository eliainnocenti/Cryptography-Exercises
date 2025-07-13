"""
AEAD AES-GCM Authenticated Encryption with PyCryptodome.
Demonstrates authenticated encryption with associated data using AES-GCM mode.
"""

from base64 import b64encode, b64decode
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def encrypt_aes_gcm(plaintext, associated_data=None, key=None):
    """Encrypt data using AES-GCM authenticated encryption.
    
    Args:
        plaintext (bytes): Data to encrypt
        associated_data (bytes): Additional data to authenticate (not encrypted)
        key (bytes): AES key (32 bytes for AES-256), generates random if None
    
    Returns:
        tuple: (ciphertext, tag, nonce, key)
    """
    # Generate key if not provided
    if key is None:
        key = get_random_bytes(AES.key_size[2])  # AES-256
    
    # Create AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM)
    
    # Add associated data for authentication (if provided)
    if associated_data:
        cipher.update(associated_data)
    
    # Encrypt and compute authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return ciphertext, tag, cipher.nonce, key

def decrypt_aes_gcm(ciphertext, tag, nonce, key, associated_data=None):
    """Decrypt and verify data using AES-GCM.
    
    Args:
        ciphertext (bytes): Encrypted data
        tag (bytes): Authentication tag
        nonce (bytes): Nonce used for encryption
        key (bytes): AES key
        associated_data (bytes): Associated data to verify
    
    Returns:
        bytes: Decrypted plaintext
    
    Raises:
        ValueError: If authentication fails
    """
    # Create AES-GCM cipher with the same nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Add associated data for verification (if provided)
    if associated_data:
        cipher.update(associated_data)
    
    # Decrypt and verify authentication tag
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext

def package_aes_gcm_json(ciphertext, tag, nonce, associated_data=None):
    """Package AES-GCM encryption result in JSON format.
    
    Args:
        ciphertext (bytes): Encrypted data
        tag (bytes): Authentication tag
        nonce (bytes): Nonce
        associated_data (bytes): Associated data (optional)
    
    Returns:
        str: JSON string containing all encryption components
    """
    # Prepare data for JSON serialization
    json_data = {
        'nonce': b64encode(nonce).decode(),
        'ciphertext': b64encode(ciphertext).decode(),
        'tag': b64encode(tag).decode(),
        'algorithm': 'AES-GCM'
    }
    
    # Include associated data if provided
    if associated_data:
        json_data['associated_data'] = b64encode(associated_data).decode()
    
    return json.dumps(json_data)

def unpack_aes_gcm_json(json_string):
    """Unpack AES-GCM components from JSON format.
    
    Args:
        json_string (str): JSON containing encryption components
    
    Returns:
        dict: Dictionary with decoded components
    """
    data = json.loads(json_string)
    
    result = {
        'nonce': b64decode(data['nonce']),
        'ciphertext': b64decode(data['ciphertext']),
        'tag': b64decode(data['tag']),
        'algorithm': data.get('algorithm', 'AES-GCM')
    }
    
    # Include associated data if present
    if 'associated_data' in data:
        result['associated_data'] = b64decode(data['associated_data'])
    
    return result

def main():
    """Demonstrate AES-GCM authenticated encryption."""
    print("=== AES-GCM Authenticated Encryption Demo ===")
    
    # Test data
    header = b"this is the authentication only part"
    plaintext = b"this is the secret part"
    
    print(f"Associated data (header): {header.decode()}")
    print(f"Plaintext to encrypt: {plaintext.decode()}")
    
    # Test 1: Basic AES-GCM encryption
    print("\n=== Test 1: Basic AES-GCM Encryption ===")
    ciphertext, tag, nonce, key = encrypt_aes_gcm(plaintext, header)
    
    print(f"Generated key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Authentication tag: {tag.hex()}")
    
    # Test 2: JSON packaging
    print("\n=== Test 2: JSON Packaging ===")
    json_package = package_aes_gcm_json(ciphertext, tag, nonce, header)
    print(f"JSON package: {json_package}")
    
    # Test 3: Decryption and verification
    print("\n=== Test 3: Decryption and Verification ===")
    try:
        # Unpack from JSON
        unpacked = unpack_aes_gcm_json(json_package)
        
        # Decrypt and verify
        decrypted = decrypt_aes_gcm(
            unpacked['ciphertext'],
            unpacked['tag'],
            unpacked['nonce'],
            key,
            unpacked.get('associated_data')
        )
        
        print(f"Decrypted plaintext: {decrypted.decode()}")
        print("✓ Authentication and decryption successful!")
        
        # Verify content matches
        assert plaintext == decrypted, "Decryption mismatch!"
        print("✓ Content verification passed")
        
    except ValueError as e:
        print(f"✗ Authentication failed: {e}")
    except Exception as e:
        print(f"✗ Error: {e}")
    
    # Test 4: Tampered data detection
    print("\n=== Test 4: Tampered Data Detection ===")
    try:
        # Tamper with the ciphertext
        tampered_ciphertext = ciphertext[:-1] + b'\x00'
        
        decrypt_aes_gcm(tampered_ciphertext, tag, nonce, key, header)
        print("✗ Failed to detect tampering!")
        
    except ValueError:
        print("✓ Tampering detected successfully!")
    
    # Test 5: Wrong associated data detection
    print("\n=== Test 5: Wrong Associated Data Detection ===")
    try:
        wrong_header = b"wrong associated data"
        decrypt_aes_gcm(ciphertext, tag, nonce, key, wrong_header)
        print("✗ Failed to detect wrong associated data!")
        
    except ValueError:
        print("✓ Wrong associated data detected successfully!")

if __name__ == "__main__":
    main()
