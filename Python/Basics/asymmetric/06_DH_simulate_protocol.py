"""
Diffie-Hellman key exchange protocol simulation.
Demonstrates DH parameter generation, key exchange, and key derivation.
"""

from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Protocol.KDF import HKDF as HKDF_pycrypto

def generate_dh_parameters(key_size=1024, generator=2):
    """Generate DH parameters for key exchange.
    
    Args:
        key_size (int): Key size in bits
        generator (int): Generator value (typically 2)
    
    Returns:
        DH parameters object
    """
    parameters = dh.generate_parameters(
        generator=generator, 
        key_size=key_size,
        backend=default_backend()
    )
    return parameters

def generate_dh_key_pair(parameters):
    """Generate DH private/public key pair.
    
    Args:
        parameters: DH parameters
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def perform_key_exchange(private_key, peer_public_key):
    """Perform DH key exchange to derive shared secret.
    
    Args:
        private_key: Own DH private key
        peer_public_key: Peer's DH public key
    
    Returns:
        bytes: Shared secret
    """
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

def derive_keys_pycrypto(shared_secret, salt, length=32):
    """Derive keys using PyCryptodome HKDF.
    
    Args:
        shared_secret (bytes): Shared DH secret
        salt (bytes): Salt for key derivation
        length (int): Derived key length
    
    Returns:
        bytes: Derived key
    """
    derived_key = HKDF_pycrypto(shared_secret, length, salt, SHA512, 1)
    return derived_key

def derive_keys_hazmat(shared_secret, info=b'handshake data', length=32):
    """Derive keys using cryptography library HKDF.
    
    Args:
        shared_secret (bytes): Shared DH secret
        info (bytes): Context information
        length (int): Derived key length
    
    Returns:
        bytes: Derived key
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
        backend=default_backend()
    )
    derived_key = kdf.derive(shared_secret)
    return derived_key

def verify_key_agreement(key1, key2):
    """Securely verify that two keys are identical.
    
    Args:
        key1 (bytes): First key
        key2 (bytes): Second key
    
    Returns:
        bool: True if keys match, False otherwise
    """
    return constant_time.bytes_eq(key1, key2)

def main():
    """Demonstrate Diffie-Hellman key exchange protocol."""
    print("=== Diffie-Hellman Key Exchange Simulation ===")
    
    # Generate DH parameters (shared between parties)
    parameters = generate_dh_parameters()
    print("✓ DH parameters generated")
    
    # === First Key Exchange ===
    print("\n=== First Key Exchange ===")
    
    # Generate key pairs for both parties
    server_private, server_public = generate_dh_key_pair(parameters)
    peer_private, peer_public = generate_dh_key_pair(parameters)
    print("✓ Key pairs generated for both parties")
    
    # Perform key exchange from both sides
    server_shared = perform_key_exchange(server_private, peer_public)
    peer_shared = perform_key_exchange(peer_private, server_public)
    
    print(f"Server shared secret: {server_shared.hex()[:32]}...")
    print(f"Peer shared secret: {peer_shared.hex()[:32]}...")
    
    # Verify both parties derived the same shared secret
    assert verify_key_agreement(server_shared, peer_shared), "Key exchange failed!"
    print("✓ Shared secrets match")
    
    # === Key Derivation ===
    print("\n=== Key Derivation ===")
    
    # Generate salt for key derivation
    salt = get_random_bytes(16)
    print(f"Salt: {salt.hex()}")
    
    # Derive keys using both methods
    derived_key_crypto = derive_keys_pycrypto(server_shared, salt)
    derived_key_hazmat = derive_keys_hazmat(server_shared)
    
    print(f"PyCryptodome derived key: {derived_key_crypto.hex()}")
    print(f"Cryptography derived key: {derived_key_hazmat.hex()}")
    
    # Verify peer derives the same keys
    peer_derived_crypto = derive_keys_pycrypto(peer_shared, salt)
    peer_derived_hazmat = derive_keys_hazmat(peer_shared)
    
    crypto_match = verify_key_agreement(derived_key_crypto, peer_derived_crypto)
    hazmat_match = verify_key_agreement(derived_key_hazmat, peer_derived_hazmat)
    
    print(f"PyCryptodome key agreement: {'✓ Success' if crypto_match else '✗ Failed'}")
    print(f"Cryptography key agreement: {'✓ Success' if hazmat_match else '✗ Failed'}")
    
    # === Second Key Exchange (ephemeral keys) ===
    print("\n=== Second Key Exchange (New Ephemeral Keys) ===")
    
    # Generate new private keys (reuse parameters)
    server_private2, server_public2 = generate_dh_key_pair(parameters)
    peer_private2, peer_public2 = generate_dh_key_pair(parameters)
    
    # Perform second key exchange
    server_shared2 = perform_key_exchange(server_private2, peer_public2)
    peer_shared2 = perform_key_exchange(peer_private2, server_public2)
    
    # Derive keys for second exchange
    derived_key2_server = derive_keys_pycrypto(server_shared2, salt)
    derived_key2_peer = derive_keys_pycrypto(peer_shared2, salt)
    
    second_match = verify_key_agreement(derived_key2_server, derived_key2_peer)
    print(f"Second key exchange: {'✓ Success' if second_match else '✗ Failed'}")
    
    # Verify that new keys are different from first exchange
    keys_different = not verify_key_agreement(derived_key_crypto, derived_key2_server)
    print(f"Forward secrecy (keys different): {'✓ Yes' if keys_different else '✗ No'}")

if __name__ == "__main__":
    main()
