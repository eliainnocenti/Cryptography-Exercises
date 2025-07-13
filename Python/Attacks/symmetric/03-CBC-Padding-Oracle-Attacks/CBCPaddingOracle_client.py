#!/usr/bin/env python3
"""
CBC Padding Oracle Attack Client

This client demonstrates the CBC padding oracle attack, which exploits
servers that reveal whether decrypted ciphertext has valid PKCS#7 padding.
This information leakage allows attackers to decrypt entire ciphertexts
without knowing the encryption key.

The attack works by:
1. Using the padding oracle to determine if decryption has valid padding
2. Systematically guessing plaintext bytes based on padding responses
3. Building the complete plaintext byte by byte

Mathematical Foundation:
- CBC decryption: P[i] = Decrypt(C[i]) XOR C[i-1]
- By controlling C[i-1], we can influence P[i]
- Valid padding reveals information about the plaintext

Usage:
    python3 CBCPaddingOracle_client.py
"""

import os
import math

# Configure pwntools to suppress unnecessary output
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES

from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext

def num_blocks(ciphertext, block_size):
    """
    Calculate the number of blocks in a ciphertext.
    
    Args:
        ciphertext (bytes): The ciphertext to analyze
        block_size (int): The block size in bytes
        
    Returns:
        int: Number of blocks
    """
    return math.ceil(len(ciphertext) / block_size)

def get_nth_block(ciphertext, n, block_size):
    """
    Extract the nth block from ciphertext (0-indexed).
    
    Args:
        ciphertext (bytes): The ciphertext
        n (int): Block index (0-based)
        block_size (int): Block size in bytes
        
    Returns:
        bytes: The nth block
    """
    return ciphertext[n * block_size:(n + 1) * block_size]

def get_n_blocks_from_m(ciphertext, n, m, block_size):
    """
    Extract n blocks starting from block m.
    
    Args:
        ciphertext (bytes): The ciphertext
        n (int): Number of blocks to extract
        m (int): Starting block index
        block_size (int): Block size in bytes
        
    Returns:
        bytes: The extracted blocks
    """
    return ciphertext[m * block_size:(m + n) * block_size]

def query_oracle(iv, ciphertext):
    """
    Query the padding oracle server with given IV and ciphertext.
    
    Args:
        iv (bytes): The initialization vector
        ciphertext (bytes): The ciphertext to test
        
    Returns:
        bool: True if padding is valid, False otherwise
    """
    try:
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ciphertext)
        response = server.recv(1024)
        server.close()
        
        response_text = response.decode()
        # Server responds "OK" for valid padding, "NO" for invalid padding
        is_valid = response_text == "OK"
        
        return is_valid
        
    except Exception as e:
        print(f"Oracle query failed: {e}")
        return False

def check_oracle_good_padding():
    """
    Test the oracle with known good padding (original ciphertext).
    """
    print("=== Testing Oracle with Good Padding ===")
    is_valid = query_oracle(iv, ciphertext)
    print(f"Oracle response for original ciphertext: {'Valid' if is_valid else 'Invalid'}")
    return is_valid

def check_oracle_bad_padding():
    """
    Test the oracle with known bad padding (modified ciphertext).
    """
    print("=== Testing Oracle with Bad Padding ===")
    
    # Modify the last byte to create invalid padding
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[-1] ^= 1  # Flip one bit
    
    is_valid = query_oracle(iv, bytes(modified_ciphertext))
    print(f"Oracle response for modified ciphertext: {'Valid' if is_valid else 'Invalid'}")
    return is_valid

def guess_byte(known_plaintext, ciphertext_block, target_ciphertext, block_size):
    """
    Guess a single byte of plaintext using the padding oracle.
    
    Args:
        known_plaintext (bytes): Already discovered plaintext bytes (from right to left)
        ciphertext_block (bytes): The ciphertext block to modify
        target_ciphertext (bytes): The complete target ciphertext
        block_size (int): Block size in bytes
        
    Returns:
        int: The guessed byte value, or None if not found
    """
    padding_value = len(known_plaintext) + 1
    print(f"Guessing byte with padding value: {padding_value}")
    
    # Create a modified ciphertext block
    modified_block = bytearray(ciphertext_block)
    
    # Set up the known bytes to produce the correct padding
    for i in range(len(known_plaintext)):
        byte_index = block_size - 1 - i
        modified_block[byte_index] ^= known_plaintext[i] ^ padding_value
    
    # Try all possible values for the target byte
    target_byte_index = block_size - 1 - len(known_plaintext)
    
    for guess in range(256):
        # Modify the target byte
        modified_block[target_byte_index] = ciphertext_block[target_byte_index] ^ guess ^ padding_value
        
        # Test with the oracle
        test_ciphertext = bytes(modified_block) + target_ciphertext
        
        if query_oracle(iv, test_ciphertext):
            print(f"✓ Found byte: {guess} ('{chr(guess) if 32 <= guess <= 126 else '?'}')")
            return guess
    
    print("✗ Failed to find byte")
    return None

def guess_byte_first_block(known_plaintext, iv, target_ciphertext, block_size):
    """
    Guess a byte from the first block using the IV as the "previous block".
    
    Args:
        known_plaintext (bytes): Already discovered plaintext bytes
        iv (bytes): The initialization vector
        target_ciphertext (bytes): The complete target ciphertext
        block_size (int): Block size in bytes
        
    Returns:
        int: The guessed byte value, or None if not found
    """
    padding_value = len(known_plaintext) + 1
    print(f"Guessing first block byte with padding value: {padding_value}")
    
    # Create a modified IV
    modified_iv = bytearray(iv)
    
    # Set up the known bytes to produce the correct padding
    for i in range(len(known_plaintext)):
        byte_index = block_size - 1 - i
        modified_iv[byte_index] ^= known_plaintext[i] ^ padding_value
    
    # Try all possible values for the target byte
    target_byte_index = block_size - 1 - len(known_plaintext)
    
    for guess in range(256):
        # Modify the target byte
        modified_iv[target_byte_index] = iv[target_byte_index] ^ guess ^ padding_value
        
        # Test with the oracle
        if query_oracle(bytes(modified_iv), target_ciphertext):
            print(f"✓ Found byte: {guess} ('{chr(guess) if 32 <= guess <= 126 else '?'}')")
            return guess
    
    print("✗ Failed to find byte")
    return None

def decrypt_block(ciphertext_block, prev_block, block_size):
    """
    Decrypt a single block using the padding oracle attack.
    
    Args:
        ciphertext_block (bytes): The ciphertext block to decrypt
        prev_block (bytes): The previous ciphertext block (or IV)
        block_size (int): Block size in bytes
        
    Returns:
        bytes: The decrypted plaintext block
    """
    print(f"=== Decrypting block ===")
    print(f"Ciphertext block: {ciphertext_block.hex()}")
    print(f"Previous block: {prev_block.hex()}")
    
    known_plaintext = []
    
    # Decrypt byte by byte from right to left
    for byte_position in range(block_size):
        print(f"\nDecrypting byte {byte_position + 1}/{block_size}")
        
        # Guess the current byte
        guessed_byte = guess_byte(known_plaintext, prev_block, ciphertext_block, block_size)
        
        if guessed_byte is None:
            print(f"Failed to decrypt byte {byte_position + 1}")
            break
            
        known_plaintext.insert(0, guessed_byte)  # Insert at beginning
        
        print(f"Decrypted so far: {bytes(known_plaintext)}")
    
    return bytes(known_plaintext)

def decrypt_ciphertext(iv, ciphertext, block_size):
    """
    Decrypt the entire ciphertext using the padding oracle attack.
    
    Args:
        iv (bytes): The initialization vector
        ciphertext (bytes): The ciphertext to decrypt
        block_size (int): Block size in bytes
        
    Returns:
        bytes: The decrypted plaintext
    """
    print("=== Starting Complete Decryption ===")
    
    n_blocks = num_blocks(ciphertext, block_size)
    print(f"Ciphertext has {n_blocks} blocks")
    
    decrypted_blocks = []
    
    # Decrypt each block
    for block_index in range(n_blocks):
        print(f"\n--- Decrypting block {block_index + 1}/{n_blocks} ---")
        
        # Get the current block
        current_block = get_nth_block(ciphertext, block_index, block_size)
        
        # Get the previous block (IV for first block)
        if block_index == 0:
            prev_block = iv
        else:
            prev_block = get_nth_block(ciphertext, block_index - 1, block_size)
        
        # Decrypt the current block
        decrypted_block = decrypt_block(current_block, prev_block, block_size)
        decrypted_blocks.append(decrypted_block)
        
        print(f"Decrypted block {block_index + 1}: {decrypted_block}")
    
    # Combine all decrypted blocks
    full_plaintext = b''.join(decrypted_blocks)
    
    # Remove PKCS#7 padding
    try:
        padding_length = full_plaintext[-1]
        if padding_length <= block_size:
            # Verify padding is valid
            padding_bytes = full_plaintext[-padding_length:]
            if all(b == padding_length for b in padding_bytes):
                unpadded_plaintext = full_plaintext[:-padding_length]
                print(f"Removed padding: {padding_length} bytes")
                return unpadded_plaintext
    except:
        pass
    
    print("Could not remove padding, returning full plaintext")
    return full_plaintext

def main():
    """Main function to execute the CBC padding oracle attack."""
    print("=== CBC Padding Oracle Attack ===")
    print("This attack exploits padding validation errors to decrypt ciphertext")
    print("without knowing the encryption key.\n")
    
    print(f"Target server: {HOST}:{PORT}")
    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    block_size = AES.block_size
    print(f"Block size: {block_size} bytes")
    
    # Test the oracle
    print("\n=== Testing Oracle ===")
    good_padding = check_oracle_good_padding()
    bad_padding = check_oracle_bad_padding()
    
    if good_padding and not bad_padding:
        print("✓ Oracle is working correctly")
    else:
        print("⚠ Oracle behavior unexpected - attack may not work")
    
    # Perform the attack
    print("\n=== Executing Attack ===")
    try:
        decrypted_plaintext = decrypt_ciphertext(iv, ciphertext, block_size)
        
        print(f"\n=== Attack Results ===")
        print(f"Decrypted plaintext (bytes): {decrypted_plaintext}")
        print(f"Decrypted plaintext (hex): {decrypted_plaintext.hex()}")
        
        try:
            plaintext_str = decrypted_plaintext.decode('utf-8')
            print(f"Decrypted plaintext (string): '{plaintext_str}'")
        except UnicodeDecodeError:
            print("Decrypted plaintext contains non-UTF8 data")
        
        print("✓ Attack completed successfully!")
        
    except Exception as e:
        print(f"✗ Attack failed: {e}")
    
    print("\n=== Security Implications ===")
    print("This attack demonstrates why:")
    print("1. Servers should not reveal padding validation errors")
    print("2. Authenticated encryption modes (GCM, CCM) should be used")
    print("3. Proper error handling is crucial for security")
    print("4. Timing attacks can also exploit similar vulnerabilities")

if __name__ == '__main__':
    main()
