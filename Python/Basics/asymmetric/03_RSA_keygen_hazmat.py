"""
RSA key generation using cryptography library (hazmat).
Demonstrates key generation, serialization, and parameter extraction.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

def generate_rsa_key_pair(key_size=2048, public_exponent=65537):
    """Generate RSA key pair using cryptography library.
    
    Args:
        key_size (int): Key size in bits (default: 2048)
        public_exponent (int): Public exponent (default: 65537)
    
    Returns:
        RSA private key object
    """
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key

def save_private_key_to_file(private_key, filename="privatekey.pem", password=None):
    """Save private key to PEM file.
    
    Args:
        private_key: RSA private key object
        filename (str): Output filename
        password (bytes): Optional password for encryption
    """
    # Choose encryption algorithm
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()
    
    # Serialize private key to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    # Write to file
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)
    
    print(f"Private key saved to {filename}")
    return pem

def extract_public_key(private_key):
    """Extract public key from private key.
    
    Args:
        private_key: RSA private key object
    
    Returns:
        RSA public key object and PEM bytes
    """
    public_key = private_key.public_key()
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_key, public_pem

def display_key_parameters(private_key):
    """Display RSA key parameters.
    
    Args:
        private_key: RSA private key object
    """
    public_key = private_key.public_key()
    private_numbers = private_key.private_numbers()
    public_numbers = public_key.public_numbers()
    
    print("RSA Key Parameters:")
    print(f"  Key size: {private_key.key_size} bits")
    print(f"  Public exponent e: {public_numbers.e}")
    print(f"  Private exponent d: {private_numbers.private_exponent}")
    print(f"  Prime p: {private_numbers.p}")
    print(f"  Prime q: {private_numbers.q}")
    print(f"  Modulus n: {public_numbers.n}")

def main():
    """Demonstrate RSA key generation with cryptography library."""
    print("=== RSA Key Generation with Cryptography Library ===")
    
    # Generate RSA key pair
    private_key = generate_rsa_key_pair()
    print("✓ RSA key pair generated")
    
    # Save private key to file
    private_pem = save_private_key_to_file(private_key)
    print("Private Key (PEM format):")
    print(private_pem.decode())
    
    # Extract and display public key
    public_key, public_pem = extract_public_key(private_key)
    print("Public Key (PEM format):")
    print(public_pem.decode())
    
    # Display key parameters
    display_key_parameters(private_key)
    
    # Cleanup
    if os.path.exists("privatekey.pem"):
        os.remove("privatekey.pem")
        print("Temporary key file removed")

if __name__ == "__main__":
    main()
