"""
SHA-256 Hashing with PyCryptodome.
Demonstrates incremental hashing and different initialization methods.
"""

from Crypto.Hash import SHA256

def hash_message_incremental(message_parts):
    """Hash a message by updating with multiple parts.
    
    Args:
        message_parts (list): List of byte strings to hash
    
    Returns:
        tuple: (digest, hexdigest)
    """
    hash_object = SHA256.new()
    
    for part in message_parts:
        hash_object.update(part)
    
    return hash_object.digest(), hash_object.hexdigest()

def hash_message_with_initial_data(initial_data, additional_parts):
    """Hash a message with initial data and additional parts.
    
    Args:
        initial_data (bytes): Initial data for hash object
        additional_parts (list): Additional parts to update
    
    Returns:
        tuple: (digest, hexdigest)
    """
    hash_object = SHA256.new(data=initial_data)
    
    for part in additional_parts:
        hash_object.update(part)
    
    return hash_object.digest(), hash_object.hexdigest()

def main():
    """Demonstrate SHA-256 hashing with different approaches."""
    print("=== SHA-256 Hashing Demo ===")
    
    # Test 1: Incremental hashing
    print("\n=== Test 1: Incremental Hashing ===")
    message_parts = [
        b'Beginning of the message to hash...',
        b'...and some more data'
    ]
    
    print("Message parts:")
    for i, part in enumerate(message_parts, 1):
        print(f"  Part {i}: {part}")
    
    digest1, hexdigest1 = hash_message_incremental(message_parts)
    print(f"Binary digest: {digest1}")
    print(f"Hexadecimal digest: {hexdigest1}")
    
    # Test 2: Hash with initial data
    print("\n=== Test 2: Hash with Initial Data ===")
    initial_data = b'First part of the message. '
    additional_parts = [
        b'Second part of the message. ',
        b'Third and last.'
    ]
    
    print(f"Initial data: {initial_data}")
    print("Additional parts:")
    for i, part in enumerate(additional_parts, 1):
        print(f"  Part {i}: {part}")
    
    digest2, hexdigest2 = hash_message_with_initial_data(initial_data, additional_parts)
    print(f"Binary digest: {digest2}")
    print(f"Hexadecimal digest: {hexdigest2}")
    
    # Test 3: Compare with single hash
    print("\n=== Test 3: Verification ===")
    combined_message = b''.join([initial_data] + additional_parts)
    single_hash = SHA256.new(combined_message)
    
    print(f"Combined message: {combined_message}")
    print(f"Single hash digest: {single_hash.hexdigest()}")
    print(f"Incremental hash matches: {hexdigest2 == single_hash.hexdigest()}")

if __name__ == "__main__":
    main()
