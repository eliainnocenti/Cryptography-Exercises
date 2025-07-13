"""
HMAC and BLAKE2b with Python's hashlib and hmac modules.
Demonstrates different approaches to message authentication.
"""

import hashlib
import hmac

from Crypto.Random import get_random_bytes

def create_hmac_sha256(message, secret_key):
    """Create HMAC-SHA256 using Python's hmac module.
    
    Args:
        message (bytes): Message to authenticate
        secret_key (bytes): Secret key for HMAC
    
    Returns:
        tuple: (digest, hexdigest)
    """
    mac_factory = hmac.new(secret_key, message, hashlib.sha256)
    return mac_factory.digest(), mac_factory.hexdigest()

def verify_hmac_sha256(message, mac_digest, secret_key):
    """Verify HMAC-SHA256 using secure comparison.
    
    Args:
        message (bytes): Original message
        mac_digest (bytes): HMAC digest to verify
        secret_key (bytes): Secret key for HMAC
    
    Returns:
        bool: True if HMAC is valid, False otherwise
    """
    expected_mac = hmac.new(secret_key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected_mac, mac_digest)

def create_blake2b_mac(message, secret_key, digest_size=32):
    """Create message authentication code using BLAKE2b.
    
    Args:
        message (bytes): Message to authenticate
        secret_key (bytes): Secret key for BLAKE2b
        digest_size (int): Output digest size in bytes
    
    Returns:
        tuple: (digest, hexdigest)
    """
    blake = hashlib.blake2b(key=secret_key, digest_size=digest_size)
    blake.update(message)
    return blake.digest(), blake.hexdigest()

def verify_blake2b_mac(message, mac_hex, secret_key, digest_size=32):
    """Verify BLAKE2b message authentication code.
    
    Args:
        message (bytes): Original message
        mac_hex (str): MAC in hexadecimal format
        secret_key (bytes): Secret key for BLAKE2b
        digest_size (int): Digest size used for MAC creation
    
    Returns:
        bool: True if MAC is valid, False otherwise
    """
    expected_blake = hashlib.blake2b(key=secret_key, digest_size=digest_size)
    expected_blake.update(message)
    expected_hex = expected_blake.hexdigest()
    
    return hmac.compare_digest(expected_hex, mac_hex)

def compare_mac_methods(message, secret_key):
    """Compare different MAC methods for the same message.
    
    Args:
        message (bytes): Message to authenticate
        secret_key (bytes): Secret key
    
    Returns:
        dict: Results from different MAC methods
    """
    # HMAC-SHA256
    hmac_digest, hmac_hex = create_hmac_sha256(message, secret_key)
    
    # BLAKE2b MAC
    blake_digest, blake_hex = create_blake2b_mac(message, secret_key)
    
    # HMAC-SHA1 (for comparison, though SHA-1 is deprecated)
    hmac_sha1 = hmac.new(secret_key, message, hashlib.sha1)
    
    return {
        'HMAC-SHA256': hmac_hex,
        'BLAKE2b': blake_hex,
        'HMAC-SHA1': hmac_sha1.hexdigest(),
        'lengths': {
            'HMAC-SHA256': len(hmac_digest),
            'BLAKE2b': len(blake_digest),
            'HMAC-SHA1': len(hmac_sha1.digest())
        }
    }

def main():
    """Demonstrate HMAC and BLAKE2b message authentication."""
    print("=== HMAC and BLAKE2b Message Authentication Demo ===")
    
    # Generate secret key
    secret = get_random_bytes(32)  # 256-bit key
    print(f"Generated secret key (256-bit): {secret.hex()}")
    
    # Test messages
    original_msg = b'This is the message'
    tampered_msg = b'This is the new message'
    
    print(f"Original message: {original_msg.decode()}")
    print(f"Tampered message: {tampered_msg.decode()}")
    
    # Test 1: HMAC-SHA256 operations
    print("\n=== Test 1: HMAC-SHA256 Operations ===")
    
    hmac_digest, hmac_hex = create_hmac_sha256(original_msg, secret)
    print(f"HMAC-SHA256@SENDER: {hmac_hex}")
    
    # Verify with original message
    is_valid_original = verify_hmac_sha256(original_msg, hmac_digest, secret)
    print(f"Original message verification: {'✓ Valid' if is_valid_original else '✗ Invalid'}")
    
    # Verify with tampered message
    is_valid_tampered = verify_hmac_sha256(tampered_msg, hmac_digest, secret)
    print(f"Tampered message verification: {'✓ Valid' if is_valid_tampered else '✗ Invalid'}")
    
    # Test 2: BLAKE2b operations
    print("\n=== Test 2: BLAKE2b Operations ===")
    
    blake_digest, blake_hex = create_blake2b_mac(original_msg, secret)
    print(f"BLAKE2b MAC: {blake_hex}")
    
    # Verify BLAKE2b MAC
    blake_valid_original = verify_blake2b_mac(original_msg, blake_hex, secret)
    blake_valid_tampered = verify_blake2b_mac(tampered_msg, blake_hex, secret)
    
    print(f"BLAKE2b original verification: {'✓ Valid' if blake_valid_original else '✗ Invalid'}")
    print(f"BLAKE2b tampered verification: {'✓ Valid' if blake_valid_tampered else '✗ Invalid'}")
    
    # Test 3: Method comparison
    print("\n=== Test 3: MAC Method Comparison ===")
    
    mac_results = compare_mac_methods(original_msg, secret)
    
    print("MAC results for the same message:")
    for method, mac_value in mac_results.items():
        if method != 'lengths':
            print(f"  {method}: {mac_value}")
    
    print("\nMAC output lengths:")
    for method, length in mac_results['lengths'].items():
        print(f"  {method}: {length} bytes ({length * 8} bits)")
    
    # Test 4: HMAC compare_digest importance
    print("\n=== Test 4: Secure Comparison Importance ===")
    print("Using hmac.compare_digest() prevents timing attacks:")
    print("  - Constant-time comparison")
    print("  - Prevents information leakage through timing")
    print("  - Always use for cryptographic comparisons")
    
    # Demonstrate timing-safe comparison
    correct_mac = hmac_hex
    wrong_mac = "0" * len(hmac_hex)
    
    safe_result = hmac.compare_digest(correct_mac, hmac_hex)
    print(f"Safe comparison (correct): {safe_result}")
    
    safe_result_wrong = hmac.compare_digest(wrong_mac, hmac_hex)
    print(f"Safe comparison (wrong): {safe_result_wrong}")
    
    # Test 5: Performance and security notes
    print("\n=== Test 5: Performance and Security Notes ===")
    print("HMAC-SHA256:")
    print("  + Standardized (RFC 2104)")
    print("  + Widely supported")
    print("  + Proven security properties")
    print()
    print("BLAKE2b:")
    print("  + Faster than HMAC-SHA256")
    print("  + Built-in keyed mode")
    print("  + Variable output length")
    print("  + Modern design (2012)")

if __name__ == "__main__":
    main()
