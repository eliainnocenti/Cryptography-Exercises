#!/usr/bin/env python3
"""
ECB Copy-and-Paste Attack Implementation

This script demonstrates the ECB copy-and-paste attack, which exploits the
deterministic nature of ECB mode to forge authentication cookies by combining
ciphertext blocks from different encrypted messages.

The attack works by:
1. Crafting specific inputs to control block boundaries
2. Generating encrypted cookies with predictable block structure
3. Copying and pasting blocks to create a forged admin cookie

Attack Strategy:
- Generate a legitimate cookie with controlled block alignment
- Craft an input that places "admin" in a separate block
- Combine blocks from both cookies to create a forged admin cookie

Usage:
    python3 copypaste_attack.py
"""

import os

# Configure pwntools to suppress unnecessary output
os.environ['PWNLIB_NOTERM'] = 'True'  # Allow pwntools to run inside IDEs
os.environ['PWNLIB_SILENT'] = 'True'  # Suppress pwntools output

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from copypaste_server_gencookie_service import profile_for, encode_profile
from myconfig import HOST, PORT, DELTA_PORT

def analyze_profile_structure(email):
    """
    Analyze the structure of the profile to understand block boundaries.
    
    Args:
        email (str): The email address to analyze
        
    Returns:
        bytes: The encoded profile
    """
    profile = profile_for(email)
    encoded_profile = encode_profile(profile)
    
    print(f"Profile for email '{email}': {profile}")
    print(f"Encoded profile: {encoded_profile}")
    print(f"Profile length: {len(encoded_profile)} bytes")
    
    # Show block breakdown
    for i in range(0, len(encoded_profile), AES.block_size):
        block = encoded_profile[i:i+AES.block_size]
        print(f"Block {i//AES.block_size}: {block}")
    
    return encoded_profile

def generate_legitimate_cookie():
    """
    Generate a legitimate encrypted cookie from the server.
    
    Returns:
        bytes: The encrypted cookie
    """
    print("=== Generating Legitimate Cookie ===")
    
    # Use a carefully crafted email to control block boundaries
    # The goal is to have "user" role in a separate block for easy replacement
    target_email = b'aaaaaaa@b.com'
    
    # Connect to the cookie generation server
    server_gencookies = remote(HOST, PORT)
    server_gencookies.send(target_email)
    encrypted_cookie = server_gencookies.recv(1024)
    server_gencookies.close()
    
    print(f"Target email: {target_email}")
    print(f"Encrypted cookie: {encrypted_cookie.hex()}")
    
    # Analyze the structure locally
    analyze_profile_structure(target_email.decode())
    
    return encrypted_cookie

def craft_admin_block():
    """
    Craft a ciphertext block containing "admin" role.
    
    Returns:
        bytes: The encrypted cookie containing the admin block
    """
    print("\n=== Crafting Admin Block ===")
    
    # Create a padded input that places "admin" in a separate block
    # The padding ensures "admin" starts at a block boundary
    padding = b'A' * 10  # Adjust padding to align "admin" at block boundary
    admin_payload = pad(b'admin', AES.block_size)
    crafted_input = padding + admin_payload
    
    print(f"Crafted input: {crafted_input}")
    print(f"Input length: {len(crafted_input)} bytes")
    
    # Generate the profile and analyze its structure
    analyze_profile_structure(crafted_input.decode())
    
    # Get the encrypted version from the server
    server_gencookies = remote(HOST, PORT)
    server_gencookies.send(crafted_input)
    encrypted_admin_cookie = server_gencookies.recv(1024)
    server_gencookies.close()
    
    print(f"Encrypted admin cookie: {encrypted_admin_cookie.hex()}")
    
    return encrypted_admin_cookie

def forge_admin_cookie(legitimate_cookie, admin_cookie):
    """
    Forge an admin cookie by combining blocks from legitimate and admin cookies.
    
    Args:
        legitimate_cookie (bytes): The legitimate encrypted cookie
        admin_cookie (bytes): The cookie containing the admin block
        
    Returns:
        bytes: The forged admin cookie
    """
    print("\n=== Forging Admin Cookie ===")
    
    # Combine the first two blocks from the legitimate cookie
    # with the admin block from the crafted cookie
    forged_cookie = legitimate_cookie[0:32] + admin_cookie[16:32]
    
    print(f"Legitimate cookie blocks 0-1: {legitimate_cookie[0:32].hex()}")
    print(f"Admin block from crafted cookie: {admin_cookie[16:32].hex()}")
    print(f"Forged admin cookie: {forged_cookie.hex()}")
    
    return forged_cookie

def test_forged_cookie(forged_cookie):
    """
    Test the forged admin cookie against the authentication server.
    
    Args:
        forged_cookie (bytes): The forged admin cookie
        
    Returns:
        str: The server's response
    """
    print("\n=== Testing Forged Cookie ===")
    
    try:
        # Connect to the test server (running on different port)
        server_test = remote(HOST, PORT + DELTA_PORT)
        server_test.send(forged_cookie)
        response = server_test.recv(1024)
        server_test.close()
        
        response_text = response.decode()
        print(f"Server response: {response_text}")
        
        return response_text
        
    except Exception as e:
        print(f"Error testing forged cookie: {e}")
        return None

def main():
    """Main function to execute the ECB copy-and-paste attack."""
    print("=== ECB Copy-and-Paste Attack ===")
    print("This attack exploits ECB mode's deterministic encryption to forge admin cookies")
    print("by combining ciphertext blocks from different encrypted messages.\n")
    
    print(f"Target servers: {HOST}:{PORT} (cookie generation), {HOST}:{PORT + DELTA_PORT} (authentication)")
    
    # Step 1: Generate a legitimate cookie
    legitimate_cookie = generate_legitimate_cookie()
    
    # Step 2: Craft a cookie containing an admin block
    admin_cookie = craft_admin_block()
    
    # Step 3: Forge an admin cookie by combining blocks
    forged_cookie = forge_admin_cookie(legitimate_cookie, admin_cookie)
    
    # Step 4: Test the forged cookie
    response = test_forged_cookie(forged_cookie)
    
    # Display results
    print(f"\n=== Attack Results ===")
    if response and "admin" in response.lower():
        print("✓ Attack successful! Admin access granted.")
    elif response:
        print("⚠ Attack failed. Server response indicates no admin access.")
    else:
        print("✗ Attack failed due to connection error.")
    
    print("\nThis demonstrates how ECB mode's deterministic encryption")
    print("allows attackers to manipulate encrypted data by copying and pasting blocks.")

if __name__ == '__main__':
    main()
