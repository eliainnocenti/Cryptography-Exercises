"""
SHA3-256 File Hashing with PyCryptodome.
Demonstrates hashing files in both text and binary modes.
"""

from Crypto.Hash import SHA3_256
import os

def hash_file_text_mode(filename):
    """Hash file content in text mode (with encoding).
    
    Args:
        filename (str): Path to file to hash
    
    Returns:
        tuple: (digest, hexdigest)
    """
    hash_gen = SHA3_256.new()
    
    with open(filename, 'r', encoding='utf-8') as f_input:
        content = f_input.read()
        hash_gen.update(content.encode('utf-8'))
    
    return hash_gen.digest(), hash_gen.hexdigest()

def hash_file_binary_mode(filename):
    """Hash file content in binary mode.
    
    Args:
        filename (str): Path to file to hash
    
    Returns:
        tuple: (digest, hexdigest)
    """
    hash_gen = SHA3_256.new()
    
    with open(filename, "rb") as f_input:
        content = f_input.read()
        hash_gen.update(content)
    
    return hash_gen.digest(), hash_gen.hexdigest()

def hash_file_chunked(filename, chunk_size=8192):
    """Hash large files in chunks to save memory.
    
    Args:
        filename (str): Path to file to hash
        chunk_size (int): Size of chunks to read (default: 8192)
    
    Returns:
        tuple: (digest, hexdigest)
    """
    hash_gen = SHA3_256.new()
    
    with open(filename, "rb") as f_input:
        while True:
            chunk = f_input.read(chunk_size)
            if not chunk:
                break
            hash_gen.update(chunk)
    
    return hash_gen.digest(), hash_gen.hexdigest()

def main():
    """Demonstrate SHA3-256 file hashing."""
    print("=== SHA3-256 File Hashing Demo ===")
    
    # Use current script file for demonstration
    filename = __file__
    print(f"Hashing file: {filename}")
    
    # Get file information
    file_size = os.path.getsize(filename)
    print(f"File size: {file_size} bytes")
    
    # Test 1: Hash in text mode
    print("\n=== Test 1: Text Mode Hashing ===")
    digest_text, hex_text = hash_file_text_mode(filename)
    print(f"Text mode digest: {hex_text}")
    
    # Test 2: Hash in binary mode
    print("\n=== Test 2: Binary Mode Hashing ===")
    digest_binary, hex_binary = hash_file_binary_mode(filename)
    print(f"Binary mode digest: {hex_binary}")
    
    # Test 3: Hash with chunked reading
    print("\n=== Test 3: Chunked Hashing ===")
    digest_chunked, hex_chunked = hash_file_chunked(filename, chunk_size=1024)
    print(f"Chunked mode digest: {hex_chunked}")
    
    # Compare results
    print("\n=== Comparison ===")
    print(f"Text mode matches binary mode: {hex_text == hex_binary}")
    print(f"Binary mode matches chunked mode: {hex_binary == hex_chunked}")
    
    if hex_text == hex_binary == hex_chunked:
        print("✓ All hashing methods produce identical results")
    else:
        print("⚠ Different hashing methods produce different results")
        print("  This is expected when comparing text vs binary mode due to encoding")

if __name__ == "__main__":
    main()
