from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

if __name__ == '__main__':
    # Generate 40 random bytes and print them.
    # This can be used as a key or other cryptographic material.
    random_key = get_random_bytes(40)
    print(f"Generated 40 random bytes (key or cryptographic material): {random_key}")

    # Generate random bytes equal to the AES block size (16 bytes for AES).
    # This is typically used for initialization vectors (IVs) or nonces.
    random_iv = get_random_bytes(AES.block_size)
    print(f"Generated {AES.block_size}-byte random value (IV or nonce): {random_iv}")
