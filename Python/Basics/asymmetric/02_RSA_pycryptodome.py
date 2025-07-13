"""
RSA operations using PyCryptodome library.
Demonstrates key generation, import/export, digital signatures, and encryption.
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import os

def generate_and_save_key(key_size=2048, filename='mykey.pem', passphrase='longpassphrasehere'):
    """Generate RSA key pair and save to file.
    
    Args:
        key_size (int): Key size in bits (default: 2048)
        filename (str): Output filename for private key
        passphrase (str): Passphrase for key protection
    
    Returns:
        RSA key object
    """
    # Generate new RSA key pair (e=65537 by default)
    key = RSA.generate(key_size)
    
    # Display the key in PEM format
    print("Generated RSA Key (PEM format):")
    print(key.export_key(format='PEM', pkcs=8).decode())
    
    # Save encrypted private key to file
    with open(filename, 'wb') as f:
        f.write(key.export_key(format='PEM', passphrase=passphrase, pkcs=8))
    
    print(f"Private key saved to {filename}")
    return key

def load_key_from_file(filename='mykey.pem', passphrase='longpassphrasehere'):
    """Load RSA key from PEM file.
    
    Args:
        filename (str): Private key filename
        passphrase (str): Passphrase for key decryption
    
    Returns:
        RSA key object
    """
    with open(filename, 'r') as f:
        key = RSA.import_key(f.read(), passphrase=passphrase)
    return key

def display_key_parameters(key):
    """Display RSA key parameters.
    
    Args:
        key: RSA key object
    """
    print("RSA Key Parameters:")
    print(f"  Modulus n: {key.n}")
    print(f"  Public exponent e: {key.e}")
    print(f"  Private exponent d: {key.d}")
    print(f"  Prime p: {key.p}")
    print(f"  Prime q: {key.q}")

def create_rsa_signature(message, private_key):
    """Create RSA-PSS digital signature.
    
    Args:
        message (bytes): Message to sign
        private_key: RSA private key
    
    Returns:
        bytes: Digital signature
    """
    # Hash the message
    h = SHA256.new(message)
    
    # Sign the hash using PSS padding
    signature = pss.new(private_key).sign(h)
    return signature

def verify_rsa_signature(message, signature, public_key):
    """Verify RSA-PSS digital signature.
    
    Args:
        message (bytes): Original message
        signature (bytes): Digital signature
        public_key: RSA public key
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Hash the message
        h = SHA256.new(message)
        
        # Verify signature using PSS padding
        verifier = pss.new(public_key)
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def rsa_encrypt_message(message, public_key):
    """Encrypt message using RSA-OAEP.
    
    Args:
        message (bytes): Message to encrypt
        public_key: RSA public key
    
    Returns:
        bytes: Encrypted message
    """
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def rsa_decrypt_message(ciphertext, private_key):
    """Decrypt message using RSA-OAEP.
    
    Args:
        ciphertext (bytes): Encrypted message
        private_key: RSA private key
    
    Returns:
        bytes: Decrypted message
    """
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def main():
    """Demonstrate RSA operations using PyCryptodome."""
    print("=== RSA with PyCryptodome Demo ===")
    
    # Generate and save key
    key = generate_and_save_key()
    
    # Load key from file
    loaded_key = load_key_from_file()
    
    # Display key parameters
    display_key_parameters(loaded_key)
    
    # Create RSA key from known parameters (verification)
    reconstructed_key = RSA.construct(
        (loaded_key.n, loaded_key.e, loaded_key.d, loaded_key.p, loaded_key.q), 
        consistency_check=True
    )
    print("✓ Key reconstruction successful")
    
    # Extract public key
    public_key = loaded_key.publickey()
    print(f"Public key: {public_key}")
    
    # === Digital Signature Demo ===
    print("\n=== Digital Signature Demo ===")
    message = b'This is the message to be signed'
    print(f"Message to sign: {message}")
    
    # Create signature
    signature = create_rsa_signature(message, loaded_key)
    print(f"Signature created (length: {len(signature)} bytes)")
    
    # Verify signature
    is_valid = verify_rsa_signature(message, signature, public_key)
    print(f"Signature verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    # === Encryption Demo ===
    print("\n=== Encryption Demo ===")
    secret_message = b'This is a secret message'
    print(f"Secret message: {secret_message}")
    
    # Encrypt with public key
    encrypted = rsa_encrypt_message(secret_message, public_key)
    print(f"Encrypted message (length: {len(encrypted)} bytes)")
    
    # Decrypt with private key
    decrypted = rsa_decrypt_message(encrypted, loaded_key)
    print(f"Decrypted message: {decrypted}")
    
    # Verify encryption/decryption
    assert secret_message == decrypted, "Encryption/decryption failed"
    print("✓ Encryption and decryption successful!")
    
    # Cleanup
    if os.path.exists('mykey.pem'):
        os.remove('mykey.pem')
        print("Temporary key file removed")

if __name__ == "__main__":
    main()
