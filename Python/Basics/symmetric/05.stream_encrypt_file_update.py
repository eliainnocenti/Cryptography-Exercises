"""
File encryption using Salsa20 stream cipher with chunked processing.
Demonstrates reading and encrypting files in chunks for memory efficiency.
"""

import base64
import sys

from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20

def encrypt_file_chunked(input_file, output_file, key=None, chunk_size=1024):
    """Encrypt a file using Salsa20 stream cipher with chunked processing.
    
    Args:
        input_file (str): Path to input file
        output_file (str): Path to output file
        key (bytes): Salsa20 key (16 bytes), generates random if None
        chunk_size (int): Size of chunks to process (default: 1024)
    
    Returns:
        tuple: (nonce, key) for decryption
    """
    # Use provided key or generate a default key
    if key is None:
        key = b'deadbeeddeadbeef'  # 16-byte key for demonstration
    
    # Generate random nonce for Salsa20
    nonce = get_random_bytes(8)
    
    # Create Salsa20 cipher object
    cipher = Salsa20.new(key, nonce)
    
    # Process file in chunks
    with open(input_file, "rb") as f_input, open(output_file, "wb") as f_output:
        while True:
            chunk = f_input.read(chunk_size)
            if not chunk:
                break
            
            # Encrypt chunk and write to output file
            encrypted_chunk = cipher.encrypt(chunk)
            f_output.write(encrypted_chunk)
    
    return cipher.nonce, key

def main():
    """Encrypt file provided as command line arguments."""
    if len(sys.argv) != 3:
        print("Usage: python 05.stream_encrypt_file_update.py <input_file> <output_file>")
        print("Example: python 05.stream_encrypt_file_update.py data.txt encrypted.bin")
        return
    
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]
    
    print(f"=== File Encryption with Salsa20 ===")
    print(f"Input file: {input_filename}")
    print(f"Output file: {output_filename}")
    
    try:
        # Encrypt the file
        nonce, key = encrypt_file_chunked(input_filename, output_filename)
        
        # Display encryption parameters for decryption
        print(f"Encryption completed successfully!")
        print(f"Key (keep secret): {key.hex()}")
        print(f"Nonce (required for decryption): {base64.b64encode(nonce).decode()}")
        
        # File size information
        import os
        input_size = os.path.getsize(input_filename)
        output_size = os.path.getsize(output_filename)
        print(f"Input file size: {input_size} bytes")
        print(f"Output file size: {output_size} bytes")
        print(f"Size difference: {output_size - input_size} bytes (stream cipher has no padding overhead)")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_filename}' not found.")
    except Exception as e:
        print(f"Error during encryption: {e}")

if __name__ == "__main__":
    main()
