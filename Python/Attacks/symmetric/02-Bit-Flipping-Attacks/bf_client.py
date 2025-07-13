#!/usr/bin/env python3
"""
CBC Bit-Flipping Attack Client

This client demonstrates how to exploit CBC mode encryption vulnerability
to escalate privileges from regular user to admin by flipping specific bits
in the ciphertext.

The attack works because:
1. CBC mode allows targeted bit manipulation in the previous block
2. Flipping a bit in ciphertext block N affects the corresponding bit in plaintext block N+1
3. We can change 'admin=0' to 'admin=1' by flipping the right bit

Attack Strategy:
1. Get a legitimate encrypted cookie with 'admin=0'
2. Identify the position of the '0' character in the cookie structure
3. Calculate which bit to flip in the previous ciphertext block
4. Flip the bit and send the modified cookie back
5. Server decrypts and grants admin access

Usage:
    python3 bf_client.py
"""

import os

# Configure pwntools to suppress unnecessary output
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from myconfig import HOST, PORT

def analyze_cookie_structure(username):
    """
    Analyze the structure of the cookie to understand block boundaries.
    
    Args:
        username (bytes): The username to analyze
        
    Returns:
        tuple: (cookie_structure, target_position)
    """
    # Recreate the cookie structure locally to understand the layout
    cookie = b'username=' + username + b',admin=0'
    padded_cookie = pad(cookie, AES.block_size)
    
    print(f"=== Cookie Structure Analysis ===")
    print(f"Username: {username}")
    print(f"Cookie: {cookie}")
    print(f"Padded cookie: {padded_cookie}")
    print(f"Cookie length: {len(padded_cookie)} bytes")
    
    # Show block breakdown
    for i in range(0, len(padded_cookie), AES.block_size):
        block = padded_cookie[i:i+AES.block_size]
        print(f"Block {i//AES.block_size}: {block}")
    
    # Find the position of the '0' in 'admin=0'
    target_char_position = cookie.index(b'0')
    print(f"Position of '0' in 'admin=0': {target_char_position}")
    
    return padded_cookie, target_char_position

def perform_bit_flipping_attack():
    """
    Execute the complete bit-flipping attack to gain admin privileges.
    
    Returns:
        bool: True if attack succeeded, False otherwise
    """
    print("=== CBC Bit-Flipping Attack ===")
    print("This attack exploits CBC mode to change 'admin=0' to 'admin=1'")
    print("by flipping a specific bit in the ciphertext.\n")
    
    # Choose a username that creates predictable cookie structure
    username = b'aldooo11'  # Chosen to align blocks properly
    
    # Analyze cookie structure
    padded_cookie, target_position = analyze_cookie_structure(username)
    
    print(f"\n=== Phase 1: Obtaining Legitimate Cookie ===")
    
    # Connect to server to get legitimate encrypted cookie
    server = remote(HOST, PORT)
    server.send(username)
    encrypted_cookie = server.recv(1024)
    server.close()
    
    print(f"Received encrypted cookie: {encrypted_cookie.hex()}")
    print(f"Cookie length: {len(encrypted_cookie)} bytes")
    
    print(f"\n=== Phase 2: Calculating Bit-Flip Position ===")
    
    # In CBC mode, to change a bit in plaintext block N, we flip the corresponding
    # bit in ciphertext block N-1
    
    # Find which block contains the target character
    target_block = target_position // AES.block_size
    position_in_block = target_position % AES.block_size
    
    print(f"Target character '0' is in block {target_block}, position {position_in_block}")
    
    # Calculate which ciphertext block to modify (previous block)
    ciphertext_block_to_modify = target_block - 1
    ciphertext_byte_position = ciphertext_block_to_modify * AES.block_size + position_in_block
    
    print(f"Need to flip bit in ciphertext block {ciphertext_block_to_modify}")
    print(f"Ciphertext byte position to modify: {ciphertext_byte_position}")
    
    # Calculate the XOR mask to change '0' (ASCII 48) to '1' (ASCII 49)
    original_char = ord('0')  # ASCII 48
    target_char = ord('1')    # ASCII 49
    xor_mask = original_char ^ target_char
    
    print(f"XOR mask to change '0' to '1': {xor_mask}")
    
    print(f"\n=== Phase 3: Executing Bit-Flip Attack ===")
    
    # Create a mutable copy of the encrypted cookie
    modified_cookie = bytearray(encrypted_cookie)
    
    # Flip the bit at the calculated position
    if ciphertext_byte_position < len(modified_cookie):
        print(f"Original byte at position {ciphertext_byte_position}: {modified_cookie[ciphertext_byte_position]}")
        modified_cookie[ciphertext_byte_position] ^= xor_mask
        print(f"Modified byte at position {ciphertext_byte_position}: {modified_cookie[ciphertext_byte_position]}")
    else:
        print("⚠ Error: Calculated position is out of bounds")
        return False
    
    print(f"Modified cookie: {bytes(modified_cookie).hex()}")
    
    print(f"\n=== Phase 4: Testing Modified Cookie ===")
    
    # Send the modified cookie back to the server
    server = remote(HOST, PORT)
    server.send(username)  # Send username first
    server.recv(1024)      # Receive the original cookie (discard)
    
    # Now send our modified cookie
    server.send(bytes(modified_cookie))
    response = server.recv(1024)
    server.close()
    
    response_text = response.decode()
    print(f"Server response: {response_text}")
    
    # Check if attack succeeded
    if "admin" in response_text.lower():
        print("✓ Attack successful! Admin access granted.")
        return True
    else:
        print("✗ Attack failed. Admin access not granted.")
        return False

def demonstrate_attack_principle():
    """
    Demonstrate the theoretical principle behind the bit-flipping attack.
    """
    print("\n=== Attack Principle Demonstration ===")
    print("CBC Bit-Flipping Attack Theory:")
    print("1. In CBC mode: P[i] = Decrypt(C[i]) XOR C[i-1]")
    print("2. To change bit j in P[i], flip bit j in C[i-1]")
    print("3. The change affects only the target bit in the next block")
    print("4. This allows precise manipulation of specific characters\n")
    
    # Show the mathematical relationship
    original_char = ord('0')
    target_char = ord('1')
    xor_mask = original_char ^ target_char
    
    print(f"Character change: '{chr(original_char)}' (ASCII {original_char}) → '{chr(target_char)}' (ASCII {target_char})")
    print(f"Binary representation:")
    print(f"  '0': {bin(original_char)} ({original_char})")
    print(f"  '1': {bin(target_char)} ({target_char})")
    print(f"  XOR mask: {bin(xor_mask)} ({xor_mask})")
    print(f"  Verification: {original_char} XOR {xor_mask} = {original_char ^ xor_mask}")

def main():
    """Main function to execute the bit-flipping attack demonstration."""
    print("=== CBC Bit-Flipping Attack Demonstration ===")
    print("This attack exploits CBC mode encryption to escalate privileges")
    print("from regular user to admin by flipping specific bits in ciphertext.\n")
    
    print(f"Target server: {HOST}:{PORT}")
    
    # Demonstrate the attack principle
    demonstrate_attack_principle()
    
    # Perform the actual attack
    success = perform_bit_flipping_attack()
    
    print(f"\n=== Attack Summary ===")
    if success:
        print("✓ Bit-flipping attack completed successfully!")
        print("✓ Successfully escalated from user to admin privileges.")
    else:
        print("✗ Bit-flipping attack failed.")
        print("⚠ This may indicate the attack parameters need adjustment.")
    
    print("\n=== Security Implications ===")
    print("This attack demonstrates why:")
    print("1. CBC mode alone is insufficient for authentication")
    print("2. Encrypted data needs integrity protection (MAC/HMAC)")
    print("3. Proper authenticated encryption modes (GCM, CCM) should be used")
    print("4. Never rely solely on encryption for data authentication")

if __name__ == '__main__':
    main()
