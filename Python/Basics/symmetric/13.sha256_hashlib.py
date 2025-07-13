"""
SHA-256 Hashing with Python's hashlib.
Demonstrates the built-in hashlib module for cryptographic hashing.
"""

import hashlib

def hash_message_incremental_hashlib(message_parts):
    """Hash message incrementally using hashlib.
    
    Args:
        message_parts (list): List of byte strings to hash
    
    Returns:
        tuple: (digest, hexdigest)
    """
    digest_object = hashlib.sha256()
    
    for part in message_parts:
        digest_object.update(part)
    
    return digest_object.digest(), digest_object.hexdigest()

def hash_single_message_hashlib(message):
    """Hash a single message using hashlib convenience function.
    
    Args:
        message (bytes): Message to hash
    
    Returns:
        tuple: (digest, hexdigest)
    """
    digest = hashlib.sha256(message).digest()
    hexdigest = hashlib.sha256(message).hexdigest()
    
    return digest, hexdigest

def compare_hash_methods(message):
    """Compare different hashing methods for the same message.
    
    Args:
        message (bytes): Message to hash with different methods
    
    Returns:
        dict: Results from different methods
    """
    # Method 1: Incremental with single update
    digest1 = hashlib.sha256()
    digest1.update(message)
    
    # Method 2: Direct hashing
    digest2 = hashlib.sha256(message)
    
    # Method 3: Incremental with multiple updates
    digest3 = hashlib.sha256()
    mid_point = len(message) // 2
    digest3.update(message[:mid_point])
    digest3.update(message[mid_point:])
    
    return {
        'incremental_single': digest1.hexdigest(),
        'direct': digest2.hexdigest(),
        'incremental_multi': digest3.hexdigest()
    }

def main():
    """Demonstrate SHA-256 hashing with hashlib."""
    print("=== SHA-256 with Python hashlib Demo ===")
    
    # Test 1: Basic incremental hashing
    print("\n=== Test 1: Basic Incremental Hashing ===")
    
    message_parts = [
        b"First sentence to hash",
        b" and second sentence to hash."
    ]
    
    print("Message parts:")
    for i, part in enumerate(message_parts, 1):
        print(f"  Part {i}: {part}")
    
    digest, hexdigest = hash_message_incremental_hashlib(message_parts)
    print(f"Binary digest: {digest}")
    print(f"Hexadecimal digest: {hexdigest}")
    
    # Test 2: Single message hashing
    print("\n=== Test 2: Single Message Hashing ===")
    
    complete_message = b"".join(message_parts)
    print(f"Complete message: {complete_message}")
    
    single_digest, single_hex = hash_single_message_hashlib(complete_message)
    print(f"Single hash digest: {single_hex}")
    
    # Verify incremental and single hashing produce same result
    print(f"Incremental matches single: {hexdigest == single_hex}")
    
    # Test 3: Compare different methods
    print("\n=== Test 3: Method Comparison ===")
    
    test_message = b"This is a test message for comparing hash methods"
    print(f"Test message: {test_message}")
    
    results = compare_hash_methods(test_message)
    print("Hash results from different methods:")
    for method, hash_value in results.items():
        print(f"  {method}: {hash_value}")
    
    # Check if all methods produce the same result
    unique_hashes = set(results.values())
    print(f"All methods produce same result: {len(unique_hashes) == 1}")
    
    # Test 4: Available hash algorithms
    print("\n=== Test 4: Available Hash Algorithms ===")
    print("Available hash algorithms in hashlib:")
    available_algos = sorted(hashlib.algorithms_available)
    for i, algo in enumerate(available_algos):
        if i % 6 == 0:  # New line every 6 algorithms
            print()
        print(f"{algo:15}", end=" ")
    print()
    
    # Test 5: Performance note
    print("\n=== Test 5: hashlib vs PyCryptodome ===")
    print("hashlib advantages:")
    print("  + Built into Python standard library")
    print("  + No external dependencies")
    print("  + Optimized implementations")
    print()
    print("PyCryptodome advantages:")
    print("  + More cryptographic primitives")
    print("  + Consistent API across algorithms")
    print("  + Advanced features (HMAC, KDF, etc.)")

if __name__ == "__main__":
    main()
