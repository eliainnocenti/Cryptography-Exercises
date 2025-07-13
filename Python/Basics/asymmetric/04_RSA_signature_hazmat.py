"""
RSA digital signatures using cryptography library (hazmat).
Demonstrates signature creation and verification with different approaches.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

def generate_rsa_key_pair(key_size=2048):
    """Generate RSA key pair.
    
    Args:
        key_size (int): Key size in bits
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def create_pss_signature(message, private_key):
    """Create RSA-PSS signature for a message.
    
    Args:
        message (bytes): Message to sign
        private_key: RSA private key
    
    Returns:
        bytes: Digital signature
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_pss_signature(message, signature, public_key):
    """Verify RSA-PSS signature.
    
    Args:
        message (bytes): Original message
        signature (bytes): Signature to verify
        public_key: RSA public key
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def create_prehashed_signature(data_parts, private_key):
    """Create signature using prehashed data.
    
    Args:
        data_parts (list): List of data parts to hash
        private_key: RSA private key
    
    Returns:
        tuple: (signature, digest)
    """
    # Create hash object and update with data parts
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    
    for part in data_parts:
        hasher.update(part)
    
    digest = hasher.finalize()
    
    # Sign the digest using prehashed approach
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )
    
    return signature, digest

def verify_prehashed_signature(data_parts, signature, public_key):
    """Verify signature using prehashed data.
    
    Args:
        data_parts (list): List of data parts to hash
        signature (bytes): Signature to verify
        public_key: RSA public key
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Recreate the hash
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash, default_backend())
        
        for part in data_parts:
            hasher.update(part)
        
        digest = hasher.finalize()
        
        # Verify the signature
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )
        return True
    except Exception:
        return False

def main():
    """Demonstrate RSA signature operations."""
    print("=== RSA Signatures with Cryptography Library ===")
    
    # Generate key pair
    private_key, public_key = generate_rsa_key_pair()
    print("✓ RSA key pair generated")
    
    # === Direct Message Signing ===
    print("\n=== Direct Message Signing ===")
    message = b'The message to sign'
    print(f"Message: {message}")
    
    # Create signature
    signature = create_pss_signature(message, private_key)
    print(f"Signature created (length: {len(signature)} bytes)")
    
    # Verify signature
    is_valid = verify_pss_signature(message, signature, public_key)
    print(f"Signature verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    # === Prehashed Signing ===
    print("\n=== Prehashed Signing ===")
    data_parts = [b"data & ", b"more data"]
    print(f"Data parts: {data_parts}")
    
    # Create prehashed signature
    prehashed_sig, digest = create_prehashed_signature(data_parts, private_key)
    print(f"Digest: {digest.hex()}")
    print(f"Prehashed signature created (length: {len(prehashed_sig)} bytes)")
    
    # Verify prehashed signature
    is_valid_prehashed = verify_prehashed_signature(data_parts, prehashed_sig, public_key)
    print(f"Prehashed signature verification: {'✓ Valid' if is_valid_prehashed else '✗ Invalid'}")

if __name__ == "__main__":
    main()
