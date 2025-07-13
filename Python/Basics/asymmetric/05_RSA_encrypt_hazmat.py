"""
RSA encryption using cryptography library (hazmat).
Demonstrates loading keys from files and OAEP encryption/decryption.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

def load_private_key_from_file(filename, password=None):
    """Load RSA private key from PEM file.
    
    Args:
        filename (str): Path to private key file
        password (bytes): Optional password for encrypted keys
    
    Returns:
        RSA private key object
    """
    try:
        with open(filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        # If file doesn't exist, generate a new key for demo purposes
        print(f"Key file {filename} not found. Generating new key...")
        return generate_and_save_key(filename)

def generate_and_save_key(filename="privatekey.pem"):
    """Generate new RSA key and save to file.
    
    Args:
        filename (str): Output filename
    
    Returns:
        RSA private key object
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Save to file
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    with open(filename, 'wb') as f:
        f.write(pem)
    
    print(f"New RSA key generated and saved to {filename}")
    return private_key

def encrypt_message_oaep(message, public_key):
    """Encrypt message using RSA-OAEP.
    
    Args:
        message (bytes): Message to encrypt
        public_key: RSA public key
    
    Returns:
        bytes: Encrypted message
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message_oaep(ciphertext, private_key):
    """Decrypt message using RSA-OAEP.
    
    Args:
        ciphertext (bytes): Encrypted message
        private_key: RSA private key
    
    Returns:
        bytes: Decrypted message
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def secure_compare(data1, data2):
    """Securely compare two byte sequences.
    
    Args:
        data1 (bytes): First data sequence
        data2 (bytes): Second data sequence
    
    Returns:
        bool: True if equal, False otherwise
    """
    return constant_time.bytes_eq(data1, data2)

def main():
    """Demonstrate RSA encryption with key loading."""
    print("=== RSA Encryption with Cryptography Library ===")
    
    # Load or generate private key
    private_key = load_private_key_from_file("privatekey.pem")
    public_key = private_key.public_key()
    print("✓ RSA key pair ready")
    
    # Message to encrypt
    message = b"encrypted data"
    print(f"Original message: {message}")
    
    # Encrypt the message
    ciphertext = encrypt_message_oaep(message, public_key)
    print(f"Encrypted message (length: {len(ciphertext)} bytes)")
    
    # Decrypt the message
    decrypted = decrypt_message_oaep(ciphertext, private_key)
    print(f"Decrypted message: {decrypted}")
    
    # Securely verify that decryption was successful
    is_equal = secure_compare(decrypted, message)
    print(f"Encryption/Decryption verification: {'✓ Success' if is_equal else '✗ Failed'}")
    
    # Cleanup
    if os.path.exists("privatekey.pem"):
        os.remove("privatekey.pem")
        print("Temporary key file removed")

if __name__ == "__main__":
    main()
