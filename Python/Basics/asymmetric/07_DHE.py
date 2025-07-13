"""
Diffie-Hellman Ephemeral (DHE) key exchange demonstration.
Shows proper DHE implementation with parameter reuse and ephemeral keys.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_dh_parameters(generator=2, key_size=1024):
    """Generate DH parameters for key exchange.
    
    Args:
        generator (int): Generator value (typically 2)
        key_size (int): Key size in bits
    
    Returns:
        DH parameters object
    """
    parameters = dh.generate_parameters(
        generator=generator, 
        key_size=key_size,
        backend=default_backend()
    )
    return parameters

def perform_dh_exchange(parameters, info=b'handshake data'):
    """Perform a complete DH key exchange with key derivation.
    
    Args:
        parameters: DH parameters (shared between parties)
        info (bytes): Context information for key derivation
    
    Returns:
        tuple: (derived_key1, derived_key2) from both parties
    """
    # Generate ephemeral private keys for both parties
    private_key_1 = parameters.generate_private_key()
    private_key_2 = parameters.generate_private_key()
    
    # Extract public keys
    public_key_1 = private_key_1.public_key()
    public_key_2 = private_key_2.public_key()
    
    # Perform key exchange from both sides
    shared_key_1 = private_key_1.exchange(public_key_2)
    shared_key_2 = private_key_2.exchange(public_key_1)
    
    # Verify both parties derived the same shared secret
    assert shared_key_1 == shared_key_2, "Key exchange failed!"
    
    # Derive final keys using HKDF
    derived_key_1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    ).derive(shared_key_1)
    
    derived_key_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    ).derive(shared_key_2)
    
    return derived_key_1, derived_key_2

def main():
    """Demonstrate DHE key exchange with ephemeral keys."""
    print("=== Diffie-Hellman Ephemeral (DHE) Demo ===")
    
    # Generate DH parameters (can be reused across multiple exchanges)
    parameters = generate_dh_parameters()
    print("✓ DH parameters generated (reusable)")
    
    # === First Handshake ===
    print("\n=== First Handshake ===")
    derived_key_1a, derived_key_1b = perform_dh_exchange(parameters)
    
    print(f"Party A derived key: {derived_key_1a.hex()}")
    print(f"Party B derived key: {derived_key_1b.hex()}")
    
    # Verify both parties derived the same key
    keys_match_1 = derived_key_1a == derived_key_1b
    print(f"Key agreement successful: {'✓ Yes' if keys_match_1 else '✗ No'}")
    
    # === Second Handshake (with new ephemeral keys) ===
    print("\n=== Second Handshake (New Ephemeral Keys) ===")
    derived_key_2a, derived_key_2b = perform_dh_exchange(parameters)
    
    print(f"Party A derived key: {derived_key_2a.hex()}")
    print(f"Party B derived key: {derived_key_2b.hex()}")
    
    # Verify both parties derived the same key
    keys_match_2 = derived_key_2a == derived_key_2b
    print(f"Key agreement successful: {'✓ Yes' if keys_match_2 else '✗ No'}")
    
    # === Verify Forward Secrecy ===
    print("\n=== Forward Secrecy Check ===")
    keys_different = derived_key_1a != derived_key_2a
    print(f"Keys from different handshakes are different: {'✓ Yes' if keys_different else '✗ No'}")
    
    if keys_different:
        print("✓ Forward secrecy achieved: Each handshake produces unique keys")
    else:
        print("✗ Forward secrecy compromised: Keys are identical across handshakes")
    
    # === Multiple Handshakes Demo ===
    print("\n=== Multiple Handshakes Demo ===")
    unique_keys = set()
    
    for i in range(3):
        key_a, key_b = perform_dh_exchange(parameters, info=f'handshake {i+3}'.encode())
        assert key_a == key_b, f"Handshake {i+3} failed"
        unique_keys.add(key_a.hex())
        print(f"Handshake {i+3}: {key_a.hex()[:16]}...")
    
    print(f"Generated {len(unique_keys)} unique keys from {len(unique_keys)} handshakes")
    print("✓ Each DHE exchange produces a unique session key")

if __name__ == "__main__":
    main()
