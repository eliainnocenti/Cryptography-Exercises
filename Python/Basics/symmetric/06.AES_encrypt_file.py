"""
File encryption using AES in CBC mode with PKCS7 padding.
Demonstrates encrypting entire files with block ciphers.
"""

import sys
import os

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def encrypt_file_aes_cbc(input_file, output_file, key_size=128):
    """Encrypt a file using AES in CBC mode.
    
    Args:
        input_file (str): Path to input file
        output_file (str): Path to output file
        key_size (int): AES key size in bits (128, 192, or 256)
    
    Returns:
        tuple: (key, iv) for decryption
    """
    # Select key size index (0=128, 1=192, 2=256 bits)
    key_size_map = {128: 0, 192: 1, 256: 2}
    key_index = key_size_map.get(key_size, 0)
    
    # Generate random AES key and initialization vector
    key = get_random_bytes(AES.key_size[key_index])
    iv = get_random_bytes(AES.block_size)
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Read, pad, and encrypt the file
    with open(input_file, "rb") as f_input:
        plaintext = f_input.read()
    
    # Pad data to match AES block size (16 bytes)
    padded_data = pad(plaintext, AES.block_size)
    
    # Encrypt the padded data
    ciphertext = cipher.encrypt(padded_data)
    
    # Write ciphertext to output file
    with open(output_file, "wb") as f_output:
        f_output.write(ciphertext)
    
    return key, iv

def display_encryption_info(input_file, output_file, key, iv):
    """Display encryption information and file statistics.
    
    Args:
        input_file (str): Path to input file
        output_file (str): Path to output file
        key (bytes): AES key used
        iv (bytes): IV used
    """
    input_size = os.path.getsize(input_file)
    output_size = os.path.getsize(output_file)
    padding_bytes = output_size - input_size
    
    print(f"=== AES File Encryption Results ===")
    print(f"Input file: {input_file} ({input_size} bytes)")
    print(f"Output file: {output_file} ({output_size} bytes)")
    print(f"Padding added: {padding_bytes} bytes")
    print(f"AES key size: {len(key) * 8} bits")
    print(f"Key (keep secret): {key.hex()}")
    print(f"IV (required for decryption): {iv.hex()}")

def main():
    """Encrypt file provided as command line arguments."""
    if len(sys.argv) != 3:
        print("Usage: python 06.AES_encrypt_file.py <input_file> <output_file>")
        print("Example: python 06.AES_encrypt_file.py document.txt encrypted.bin")
        return
    
    input_filename = sys.argv[1]
    output_filename = sys.argv[2]
    
    try:
        # Encrypt the file using AES-128 by default
        key, iv = encrypt_file_aes_cbc(input_filename, output_filename, key_size=128)
        
        # Display encryption information
        display_encryption_info(input_filename, output_filename, key, iv)
        
        print("✓ File encryption completed successfully!")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_filename}' not found.")
    except Exception as e:
        print(f"Error during encryption: {e}")

if __name__ == "__main__":
    main()
