"""
Key Derivation with scrypt using PyCryptodome.
Demonstrates secure password-based key derivation with different parameter sets.
"""

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import time

def derive_key_scrypt(password, salt, key_length=16, n=2**14, r=8, p=1):
    """Derive key from password using scrypt KDF.
    
    Args:
        password (bytes): Password to derive key from
        salt (bytes): Random salt for key derivation
        key_length (int): Length of derived key in bytes
        n (int): CPU/memory cost parameter
        r (int): Block size parameter
        p (int): Parallelization parameter
    
    Returns:
        bytes: Derived key
    """
    return scrypt(password, salt, key_length, N=n, r=r, p=p)

def benchmark_scrypt_parameters(password, salt, parameter_sets):
    """Benchmark different scrypt parameter sets.
    
    Args:
        password (bytes): Password for testing
        salt (bytes): Salt for testing
        parameter_sets (list): List of (name, n, r, p) tuples
    
    Returns:
        dict: Benchmark results
    """
    results = {}
    
    for name, n, r, p in parameter_sets:
        print(f"Testing {name} parameters (N={n}, r={r}, p={p})...")
        
        start_time = time.time()
        key = derive_key_scrypt(password, salt, n=n, r=r, p=p)
        end_time = time.time()
        
        duration = end_time - start_time
        results[name] = {
            'parameters': (n, r, p),
            'duration': duration,
            'key': key.hex()
        }
        
        print(f"  Duration: {duration:.3f} seconds")
        print(f"  Key: {key.hex()}")
    
    return results

def generate_secure_salt(length=16):
    """Generate cryptographically secure salt.
    
    Args:
        length (int): Salt length in bytes
    
    Returns:
        bytes: Random salt
    """
    return get_random_bytes(length)

def main():
    """Demonstrate scrypt key derivation."""
    print("=== scrypt Key Derivation Demo ===")
    
    # Test password
    password = b'W34kpassw0rd!'
    print(f"Password: {password.decode()}")
    
    # Generate salt
    salt = generate_secure_salt(16)
    print(f"Salt (16 bytes): {salt.hex()}")
    
    # Test 1: Standard scrypt parameters
    print("\n=== Test 1: Standard Parameters ===")
    
    # Interactive login parameters (≤100ms)
    interactive_key = derive_key_scrypt(password, salt, key_length=16, n=2**14, r=8, p=1)
    print(f"Interactive login key (2^14, 8, 1): {interactive_key.hex()}")
    
    # File encryption parameters (≤5s)
    file_key = derive_key_scrypt(password, salt, key_length=32, n=2**20, r=8, p=1)
    print(f"File encryption key (2^20, 8, 1): {file_key.hex()}")
    
    # Test 2: Different key lengths
    print("\n=== Test 2: Different Key Lengths ===")
    for key_len in [16, 24, 32]:
        key = derive_key_scrypt(password, salt, key_length=key_len)
        print(f"Key length {key_len} bytes: {key.hex()}")
    
    # Test 3: Parameter recommendations
    print("\n=== Test 3: Parameter Recommendations ===")
    print("Based on Colin Percival's 2009 recommendations:")
    print("- Interactive logins: N=2^14, r=8, p=1 (≤100ms)")
    print("- File encryption: N=2^20, r=8, p=1 (≤5s)")
    print("- Source: http://www.tarsnap.com/scrypt/scrypt-slides.pdf")
    
    # Test 4: Performance benchmarking
    print("\n=== Test 4: Performance Benchmarking ===")
    parameter_sets = [
        ("Fast", 2**12, 8, 1),      # Very fast for testing
        ("Interactive", 2**14, 8, 1),  # Interactive login
        ("Moderate", 2**16, 8, 1),     # Moderate security
        # ("Strong", 2**20, 8, 1),       # File encryption (commented out - takes ~5s)
    ]
    
    benchmark_results = benchmark_scrypt_parameters(password, salt, parameter_sets)
    
    # Test 5: Salt importance
    print("\n=== Test 5: Salt Importance ===")
    salt1 = generate_secure_salt(16)
    salt2 = generate_secure_salt(16)
    
    key1 = derive_key_scrypt(password, salt1)
    key2 = derive_key_scrypt(password, salt2)
    
    print(f"Same password, salt 1: {key1.hex()}")
    print(f"Same password, salt 2: {key2.hex()}")
    print(f"Keys are different: {key1 != key2}")
    print("✓ Different salts produce different keys (prevents rainbow table attacks)")
    
    # Security note
    print("\n=== Security Notes ===")
    print("- Always store the salt alongside the derived key")
    print("- Use unique salts for each password")
    print("- Choose parameters based on your security/performance requirements")
    print("- Higher N values increase memory and CPU requirements")

if __name__ == "__main__":
    main()
