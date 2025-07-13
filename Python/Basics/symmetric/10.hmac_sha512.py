"""
HMAC-SHA512 Message Authentication with PyCryptodome.
Demonstrates HMAC creation, verification, and JSON packaging.
"""

import base64
import json

from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA512

def generate_hmac_key(key_size=32):
    """Generate cryptographically secure HMAC key.
    
    Args:
        key_size (int): Key size in bytes (default: 32)
    
    Returns:
        bytes: Random key for HMAC
    """
    return get_random_bytes(key_size)

def create_hmac_sha512(message, secret_key):
    """Create HMAC-SHA512 for a message.
    
    Args:
        message (bytes): Message to authenticate
        secret_key (bytes): Secret key for HMAC
    
    Returns:
        str: HMAC as hexadecimal string
    """
    hmac_gen = HMAC.new(secret_key, digestmod=SHA512)
    
    # Support incremental updates for large messages
    if isinstance(message, (list, tuple)):
        for part in message:
            hmac_gen.update(part)
    else:
        hmac_gen.update(message)
    
    return hmac_gen.hexdigest()

def verify_hmac_sha512(message, mac_hex, secret_key):
    """Verify HMAC-SHA512 for a message.
    
    Args:
        message (bytes): Original message
        mac_hex (str): HMAC in hexadecimal format
        secret_key (bytes): Secret key for HMAC
    
    Returns:
        bool: True if HMAC is valid, False otherwise
    """
    try:
        hmac_ver = HMAC.new(secret_key, digestmod=SHA512)
        
        if isinstance(message, (list, tuple)):
            for part in message:
                hmac_ver.update(part)
        else:
            hmac_ver.update(message)
        
        hmac_ver.hexverify(mac_hex)
        return True
    except ValueError:
        return False

def package_message_with_hmac(message, secret_key):
    """Package message with HMAC in JSON format.
    
    Args:
        message (bytes): Message to package
        secret_key (bytes): Secret key for HMAC
    
    Returns:
        str: JSON string containing message and HMAC
    """
    mac = create_hmac_sha512(message, secret_key)
    
    json_dict = {
        "message": message.decode('utf-8'),
        "MAC": mac,
        "algorithm": "HMAC-SHA512"
    }
    
    return json.dumps(json_dict)

def verify_packaged_message(json_string, secret_key):
    """Verify message and HMAC from JSON package.
    
    Args:
        json_string (str): JSON containing message and HMAC
        secret_key (bytes): Secret key for verification
    
    Returns:
        tuple: (is_valid, message, algorithm)
    """
    try:
        data = json.loads(json_string)
        message = data["message"].encode('utf-8')
        mac = data["MAC"]
        algorithm = data.get("algorithm", "HMAC-SHA512")
        
        is_valid = verify_hmac_sha512(message, mac, secret_key)
        return is_valid, message, algorithm
    
    except (json.JSONDecodeError, KeyError):
        return False, None, None

def main():
    """Demonstrate HMAC-SHA512 operations."""
    print("=== HMAC-SHA512 Message Authentication Demo ===")
    
    # Generate secret key
    secret = generate_hmac_key(32)  # 256-bit key
    print(f"Generated secret key (256-bit): {base64.b64encode(secret).decode()}")
    
    # Test message
    msg = b'This is the message to use. Now compute the SHA512-HMAC'
    print(f"Test message: {msg.decode()}")
    
    # Test 1: Basic HMAC creation and verification
    print("\n=== Test 1: Basic HMAC Operations ===")
    mac = create_hmac_sha512(msg, secret)
    print(f"Computed HMAC (SHA512): {mac}")
    
    # Verify HMAC
    is_valid = verify_hmac_sha512(msg, mac, secret)
    print(f"HMAC verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    # Test 2: Incremental HMAC (for large messages)
    print("\n=== Test 2: Incremental HMAC ===")
    message_parts = [msg[:10], msg[10:]]
    print(f"Message parts: {[part.decode() for part in message_parts]}")
    
    incremental_mac = create_hmac_sha512(message_parts, secret)
    print(f"Incremental HMAC: {incremental_mac}")
    print(f"Matches single HMAC: {mac == incremental_mac}")
    
    # Test 3: JSON packaging
    print("\n=== Test 3: JSON Packaging ===")
    json_package = package_message_with_hmac(msg, secret)
    print(f"JSON package: {json_package}")
    
    # Verify packaged message
    is_valid, verified_msg, algorithm = verify_packaged_message(json_package, secret)
    print(f"Package verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
    print(f"Verified message: {verified_msg.decode() if verified_msg else 'None'}")
    print(f"Algorithm: {algorithm}")
    
    # Test 4: Tampered message detection
    print("\n=== Test 4: Tampered Message Detection ===")
    tampered_msg = b'This is the tampered message!'
    is_tampered = verify_hmac_sha512(tampered_msg, mac, secret)
    print(f"Tampered message verification: {'✗ Detected tampering' if not is_tampered else '✓ Valid'}")

if __name__ == "__main__":
    main()
