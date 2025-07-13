"""
Trivial RSA implementation demonstrating key generation, encryption, and decryption.
This script shows the basic mathematical operations behind RSA cryptography.
"""

from Crypto.Util import number
from math import gcd

def generate_rsa_keys(key_size=1024):
    """Generate RSA public and private key pairs.
    
    Args:
        key_size (int): Size of the modulus in bits (default: 1024)
    
    Returns:
        tuple: (public_key, private_key) where each key is a tuple (exponent, modulus)
    """
    # Generate two distinct prime numbers
    p1 = number.getPrime(key_size)
    p2 = number.getPrime(key_size)
    
    # Calculate the modulus n = p * q
    n = p1 * p2
    
    # Calculate Euler's totient function phi(n) = (p-1)(q-1)
    phi = (p1 - 1) * (p2 - 1)
    
    # Choose public exponent e (commonly 65537)
    e = 65537
    
    # Verify that gcd(e, phi) = 1
    if gcd(e, phi) != 1:
        raise ValueError("e and phi(n) are not coprime")
    
    # Calculate private exponent d such that e * d ≡ 1 (mod phi)
    d = pow(e, -1, phi)
    
    # Verify the key pair
    assert (e * d) % phi == 1, "Key generation verification failed"
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key, (p1, p2)

def rsa_encrypt(message, public_key):
    """Encrypt a message using RSA public key.
    
    Args:
        message (bytes): Message to encrypt
        public_key (tuple): (e, n) public key pair
    
    Returns:
        int: Encrypted message as integer
    """
    e, n = public_key
    
    # Convert message to integer
    m_int = int.from_bytes(message, byteorder='big')
    
    # Verify message is smaller than modulus
    if m_int >= n:
        raise ValueError("Message too large for key size")
    
    # Encrypt: c = m^e mod n
    ciphertext = pow(m_int, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key, key_size):
    """Decrypt a ciphertext using RSA private key.
    
    Args:
        ciphertext (int): Encrypted message as integer
        private_key (tuple): (d, n) private key pair
        key_size (int): Key size in bits for proper byte conversion
    
    Returns:
        bytes: Decrypted message
    """
    d, n = private_key
    
    # Decrypt: m = c^d mod n
    m_int = pow(ciphertext, d, n)
    
    # Convert back to bytes
    byte_length = (key_size + 7) // 8  # Convert bits to bytes
    message = m_int.to_bytes(byte_length, byteorder='big')
    
    # Remove padding zeros and return
    return message.lstrip(b'\x00')

def main():
    """Demonstrate RSA key generation, encryption, and decryption."""
    print("=== RSA Trivial Implementation Demo ===")
    
    # Key generation
    key_size = 1024
    public_key, private_key, (p1, p2) = generate_rsa_keys(key_size)
    e, n = public_key
    d, _ = private_key
    
    print(f"Prime p1: {p1}")
    print(f"Prime p2: {p2}")
    print(f"Modulus n: {n}")
    print(f"Public exponent e: {e}")
    print(f"Private exponent d: {d}")
    
    # Message encryption and decryption


    message = b'this is the message to encrypt'
    print(f"Original message: {message}")
    
    # Encrypt the message
    ciphertext = rsa_encrypt(message, public_key)
    print(f"Encrypted message: {ciphertext}")
    
    # Decrypt the message
    decrypted = rsa_decrypt(ciphertext, private_key, key_size)
    print(f"Decrypted message: {decrypted}")
    print(f"Decrypted as string: {decrypted.decode()}")
    
    # Verify encryption/decryption worked correctly
    assert message == decrypted, "Encryption/decryption failed"
    print("✓ Encryption and decryption successful!")

if __name__ == "__main__":
    main()
