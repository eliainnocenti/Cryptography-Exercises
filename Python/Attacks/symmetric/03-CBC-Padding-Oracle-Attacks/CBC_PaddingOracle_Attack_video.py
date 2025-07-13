#!/usr/bin/env python3
"""
CBC Padding Oracle Attack Implementation

This script demonstrates a practical CBC padding oracle attack that can decrypt
arbitrary ciphertexts by exploiting information leakage in padding validation.

The Attack Process:
1. Takes the last two blocks of the ciphertext
2. Systematically modifies bytes in the second-to-last block
3. Observes server responses to determine valid padding
4. Uses XOR relationships to recover plaintext bytes
5. Repeats for all bytes in the block

Mathematical Foundation:
In CBC mode: P_i = D_K(C_i) ⊕ C_{i-1}
By manipulating C_{i-1}, we can control the plaintext P_i
If we know the padding byte, we can work backwards to find the original plaintext

Educational Purpose:
This demonstrates why cryptographic implementations must not leak information
about internal operations like padding validation.
"""

import os
# Suppress pwntools output for cleaner demonstration
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext

from Crypto.Cipher import AES


def test_padding_oracle(iv, ciphertext):
    """
    Test the padding oracle with given IV and ciphertext.
    
    Args:
        iv (bytes): Initialization vector
        ciphertext (bytes): Ciphertext to test
        
    Returns:
        bool: True if padding is valid, False otherwise
    """
    try:
        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ciphertext)
        response = server.recv(1024)
        server.close()
        return response == b'OK'
    except Exception as e:
        print(f"Error testing padding oracle: {e}")
        return False


def decrypt_last_byte(initial_part, block_to_modify, last_block, iv):
    """
    Decrypt the last byte of a block using padding oracle attack.
    
    Args:
        initial_part (bytes): Preceding ciphertext blocks
        block_to_modify (bytearray): Block that will be modified to control plaintext
        last_block (bytes): Target block to decrypt
        iv (bytes): Initialization vector
        
    Returns:
        tuple: (modified_byte_value, plaintext_byte_value)
    """
    byte_index = AES.block_size - 1  # Last byte position
    original_byte = block_to_modify[byte_index]
    
    print(f"Attacking byte at position {byte_index}")
    
    # Try all possible byte values (0-255)
    for candidate_byte in range(256):
        block_to_modify[byte_index] = candidate_byte
        test_ciphertext = initial_part + block_to_modify + last_block
        
        # Test if this produces valid padding
        if test_padding_oracle(iv, test_ciphertext):
            print(f"Found valid padding with modified byte: {candidate_byte}")
            
            # Calculate the intermediate state and original plaintext
            # When padding is valid with value 0x01, we know:
            # P'[15] = 0x01, where P' is the modified plaintext
            # P'[15] = D_K(C[15]) ⊕ C'[14]
            # So: D_K(C[15]) = P'[15] ⊕ C'[14] = 0x01 ⊕ candidate_byte
            intermediate_state = candidate_byte ^ 0x01
            
            # Original plaintext byte:
            # P[15] = D_K(C[15]) ⊕ C[14] = intermediate_state ⊕ original_byte
            plaintext_byte = intermediate_state ^ original_byte
            
            print(f"Intermediate state: {intermediate_state}")
            print(f"Original plaintext byte: {plaintext_byte} ('{chr(plaintext_byte)}' if printable)")
            
            return candidate_byte, plaintext_byte
    
    print("No valid padding found!")
    return None, None


def decrypt_second_to_last_byte(initial_part, block_to_modify, last_block, iv, 
                               known_intermediate_last):
    """
    Decrypt the second-to-last byte using known information from the last byte.
    
    Args:
        initial_part (bytes): Preceding ciphertext blocks
        block_to_modify (bytearray): Block that will be modified
        last_block (bytes): Target block to decrypt
        iv (bytes): Initialization vector
        known_intermediate_last (int): Known intermediate state of last byte
        
    Returns:
        tuple: (modified_byte_value, plaintext_byte_value)
    """
    # Set up the last byte to produce padding value 0x02
    last_byte_index = AES.block_size - 1
    block_to_modify[last_byte_index] = known_intermediate_last ^ 0x02
    
    # Now attack the second-to-last byte
    byte_index = AES.block_size - 2
    original_byte = block_to_modify[byte_index]
    
    print(f"Attacking byte at position {byte_index}")
    
    # Try all possible byte values for the second-to-last byte
    for candidate_byte in range(256):
        block_to_modify[byte_index] = candidate_byte
        test_ciphertext = initial_part + block_to_modify + last_block
        
        # Test if this produces valid padding (0x0202)
        if test_padding_oracle(iv, test_ciphertext):
            print(f"Found valid padding with modified byte: {candidate_byte}")
            
            # Calculate intermediate state and original plaintext
            # P'[14] = 0x02, so D_K(C[14]) = 0x02 ⊕ candidate_byte
            intermediate_state = candidate_byte ^ 0x02
            plaintext_byte = intermediate_state ^ original_byte
            
            print(f"Intermediate state: {intermediate_state}")
            print(f"Original plaintext byte: {plaintext_byte} ('{chr(plaintext_byte)}' if printable)")
            
            return candidate_byte, plaintext_byte
    
    print("No valid padding found!")
    return None, None


def main():
    """
    Main function demonstrating the CBC padding oracle attack.
    
    This implementation shows how to decrypt the last two bytes of a ciphertext
    block by exploiting the padding oracle vulnerability.
    """
    print("=== CBC Padding Oracle Attack Demo ===")
    print(f"Target ciphertext length: {len(ciphertext)} bytes")
    print(f"Number of blocks: {len(ciphertext) // AES.block_size}")
    
    # Calculate block structure
    num_blocks = len(ciphertext) // AES.block_size
    
    # Split ciphertext into components for the attack
    initial_part = ciphertext[:(num_blocks - 2) * AES.block_size]
    block_to_modify = bytearray(ciphertext[(num_blocks - 2) * AES.block_size:(num_blocks - 1) * AES.block_size])
    last_block = ciphertext[(num_blocks - 1) * AES.block_size:]
    
    print(f"Initial part: {len(initial_part)} bytes")
    print(f"Block to modify: {len(block_to_modify)} bytes")
    print(f"Last block: {len(last_block)} bytes")
    
    # Attack the last byte
    print("\n--- Attacking Last Byte ---")
    modified_byte_15, plaintext_byte_15 = decrypt_last_byte(
        initial_part, block_to_modify, last_block, iv
    )
    
    if modified_byte_15 is not None:
        # Calculate intermediate state for use in next byte attack
        intermediate_state_15 = modified_byte_15 ^ 0x01
        
        print("\n--- Attacking Second-to-Last Byte ---")
        modified_byte_14, plaintext_byte_14 = decrypt_second_to_last_byte(
            initial_part, block_to_modify, last_block, iv, intermediate_state_15
        )
        
        if modified_byte_14 is not None:
            print(f"\n=== Attack Results ===")
            print(f"Last byte (pos 15): {plaintext_byte_15} ('{chr(plaintext_byte_15) if 32 <= plaintext_byte_15 <= 126 else '?'}')")
            print(f"Second-to-last byte (pos 14): {plaintext_byte_14} ('{chr(plaintext_byte_14) if 32 <= plaintext_byte_14 <= 126 else '?'}')")
            
            # Show the partial decryption
            print(f"\nPartial plaintext (last 2 bytes): {bytes([plaintext_byte_14, plaintext_byte_15])}")
    
    print("\n=== Security Lessons ===")
    print("1. Never leak information about padding validation")
    print("2. Use authenticated encryption (like AES-GCM) instead of CBC")
    print("3. Implement constant-time operations for cryptographic primitives")
    print("4. This attack works because the server reveals padding validity")


if __name__ == '__main__':
    main()
