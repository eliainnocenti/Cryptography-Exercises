#!/usr/bin/env python3
"""
ECB vs CBC Mode Detection Client

This client demonstrates how to detect whether a server is using ECB or CBC
mode encryption by analyzing ciphertext patterns. The detection is based on
the fundamental difference between these modes:

- ECB: Encrypts identical plaintext blocks to identical ciphertext blocks
- CBC: Uses chaining that makes identical plaintext blocks produce different ciphertext

The client sends carefully crafted input to create identical plaintext blocks
and analyzes the resulting ciphertext to determine the encryption mode.

Usage:
    python3 client.py
"""

import os
from math import ceil

# Configure pwntools to suppress unnecessary output
os.environ['PWNLIB_NOTERM'] = 'True'  # Allow pwntools to run inside IDEs
os.environ['PWNLIB_SILENT'] = 'True'  # Suppress pwntools output

from pwn import *
from Crypto.Cipher import AES
from myconfig import HOST, PORT

def analyze_server_message_format():
    """
    Analyze the server's message format to understand how to craft the attack.
    
    The server formats messages as: "This is what I received: {input} -- END OF MESSAGE"
    We need to understand the structure to create identical blocks.
    """
    start_str = "This is what I received: "
    end_str = " -- END OF MESSAGE"
    
    print("=== Server Message Format Analysis ===")
    print(f"Message prefix: '{start_str}'")
    print(f"Prefix length: {len(start_str)} bytes")
    print(f"Message suffix: '{end_str}'")
    print(f"Suffix length: {len(end_str)} bytes")
    
    return start_str, end_str

def craft_detection_payload(start_str):
    """
    Craft a payload that will create identical plaintext blocks.
    
    Args:
        start_str (str): The server's message prefix
        
    Returns:
        bytes: The crafted payload
    """
    BLOCK_SIZE = AES.block_size
    
    # Calculate padding needed to align with block boundaries
    pad_len = ceil(len(start_str) / BLOCK_SIZE) * BLOCK_SIZE - len(start_str)
    
    # Create a payload with identical blocks
    # We send 2 blocks of 'A' characters plus padding to align boundaries
    payload = b"A" * (2 * BLOCK_SIZE + pad_len)
    
    print(f"=== Crafting Detection Payload ===")
    print(f"Padding length needed: {pad_len} bytes")
    print(f"Payload length: {len(payload)} bytes")
    print(f"Payload: {payload}")
    
    return payload

def send_payload_and_receive_response(payload):
    """
    Send the crafted payload to the server and receive the encrypted response.
    
    Args:
        payload (bytes): The payload to send
        
    Returns:
        bytes: The encrypted response from the server
    """
    print(f"\n=== Sending Payload to Server ===")
    print(f"Target server: {HOST}:{PORT}")
    
    # Connect to the server
    server = remote(HOST, PORT)
    
    # Send the payload
    print(f"Sending payload: {payload}")
    server.send(payload)
    
    # Receive the encrypted response
    ciphertext = server.recv(1024)
    server.close()
    
    print(f"Received ciphertext: {ciphertext.hex()}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    return ciphertext

def analyze_ciphertext_blocks(ciphertext):
    """
    Analyze the ciphertext blocks to detect the encryption mode.
    
    Args:
        ciphertext (bytes): The encrypted response from the server
        
    Returns:
        str: The detected encryption mode ('ECB' or 'CBC')
    """
    BLOCK_SIZE = AES.block_size
    BLOCK_SIZE_HEX = 2 * BLOCK_SIZE
    
    print(f"\n=== Analyzing Ciphertext Blocks ===")
    
    # Convert to hex for easier analysis
    ciphertext_hex = ciphertext.hex()
    
    # Display each block
    print("Ciphertext blocks:")
    blocks = []
    for i in range(0, len(ciphertext_hex), BLOCK_SIZE_HEX):
        block = ciphertext_hex[i:i + BLOCK_SIZE_HEX]
        blocks.append(block)
        print(f"Block {i//BLOCK_SIZE_HEX}: {block}")
    
    # Analyze blocks to detect mode
    # In ECB mode, identical plaintext blocks produce identical ciphertext blocks
    # We compare blocks that should contain identical plaintext
    
    print(f"\n=== Mode Detection Analysis ===")
    
    if len(ciphertext) >= 4 * BLOCK_SIZE:
        # Compare blocks 2 and 3 (should contain identical 'A' characters)
        block2 = ciphertext[2 * BLOCK_SIZE:3 * BLOCK_SIZE]
        block3 = ciphertext[3 * BLOCK_SIZE:4 * BLOCK_SIZE]
        
        print(f"Block 2: {block2.hex()}")
        print(f"Block 3: {block3.hex()}")
        
        if block2 == block3:
            detected_mode = "ECB"
            print("✓ Blocks 2 and 3 are identical → ECB mode detected")
            print("  In ECB mode, identical plaintext blocks produce identical ciphertext")
        else:
            detected_mode = "CBC"
            print("✓ Blocks 2 and 3 are different → CBC mode detected")
            print("  In CBC mode, chaining makes identical plaintext blocks produce different ciphertext")
    else:
        print("⚠ Insufficient ciphertext length for reliable mode detection")
        detected_mode = "Unknown"
    
    return detected_mode

def main():
    """Main function to execute the ECB vs CBC detection attack."""
    print("=== ECB vs CBC Mode Detection Attack ===")
    print("This client detects the encryption mode by analyzing ciphertext patterns.")
    print("The attack exploits the fundamental difference between ECB and CBC modes.\n")
    
    # Step 1: Analyze server message format
    start_str, end_str = analyze_server_message_format()
    
    # Step 2: Craft detection payload
    payload = craft_detection_payload(start_str)
    
    # Step 3: Send payload and receive response
    ciphertext = send_payload_and_receive_response(payload)
    
    # Step 4: Analyze ciphertext to detect mode
    detected_mode = analyze_ciphertext_blocks(ciphertext)
    
    # Display results
    print(f"\n=== Detection Results ===")
    print(f"Detected encryption mode: {detected_mode}")
    
    if detected_mode == "ECB":
        print("⚠ WARNING: ECB mode is vulnerable to various attacks!")
        print("  - Copy-and-paste attacks")
        print("  - Chosen-plaintext attacks")
        print("  - Pattern analysis attacks")
    elif detected_mode == "CBC":
        print("✓ CBC mode provides better security than ECB")
        print("  - Chaining prevents identical block patterns")
        print("  - However, still vulnerable to some attacks if not properly implemented")
    
    print(f"\nThis demonstrates why ECB mode should be avoided in practice.")

if __name__ == '__main__':
    main()
