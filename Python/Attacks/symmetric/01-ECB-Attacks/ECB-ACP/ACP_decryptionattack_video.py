#!/usr/bin/env python3
"""
AES-ECB Adaptive Chosen-Plaintext Attack - Video Tutorial Implementation

This script demonstrates a step-by-step implementation of an ACP attack against
an ECB encryption oracle, as would be explained in a video tutorial.

The attack progressively builds understanding by:
1. Analyzing the message structure and block boundaries
2. Demonstrating how to discover the first character
3. Extending the attack to discover the entire secret

Educational Purpose:
This implementation shows the learning progression from basic concept to
complete attack, making it ideal for understanding the methodology.

Usage:
    python3 ACP_decryptionattack_video.py
"""

import os
import string
from math import ceil

# Configure pwntools to work in IDE environments
os.environ['PWNLIB_NOTERM'] = 'True'  # Allow pwntools to run inside IDEs
os.environ['PWNLIB_SILENT'] = 'True'  # Suppress pwntools output

from pwn import *
from Crypto.Cipher import AES
from myconfig import HOST, PORT

def analyze_message_structure():
    """
    Analyze the structure of the message to understand block boundaries.
    
    This function demonstrates how to break down the oracle's message format
    to plan the attack strategy.
    """
    print("=== Message Structure Analysis ===")
    
    # The oracle encrypts: "Here is the msg:{input} - and the sec:{secret}"
    prefix = b'Here is the msg:'
    postfix = b' - and the sec:'
    
    print(f"Prefix length: {len(prefix)} bytes")    # 16 bytes (exactly 1 block)
    print(f"Postfix length: {len(postfix)} bytes")  # 15 bytes
    
    # Show how blocks are aligned
    print("\nBlock structure with different inputs:")
    test_inputs = [b'', b'A', b'A'*10, b'A'*15]
    
    for test_input in test_inputs:
        full_message = prefix + test_input + postfix + b'?' * 16  # Simulated secret
        print(f"\nInput: {test_input}")
        print(f"Full message length: {len(full_message)} bytes")
        
        # Show block breakdown
        for i in range(ceil(len(full_message) / AES.block_size)):
            block = full_message[i*16:(i+1)*16]
            print(f"Block {i}: {block}")

def discover_first_character():
    """
    Demonstrate how to discover the first character of the secret.
    
    This function shows the basic principle of the attack by comparing
    ciphertext blocks to identify when a guess is correct.
    
    Returns:
        str: The first character of the secret
    """
    print("\n=== Discovering First Character ===")
    
    # Fixed parts of the message
    prefix = b'Here is the msg:'
    postfix = b' - and the sec:'
    
    # Try each printable character as the first character of the secret
    for guess in string.printable:
        # Construct a message where the guessed character appears in a predictable position
        message = postfix + guess.encode()
        
        try:
            # Connect to the encryption oracle
            server = remote(HOST, PORT)
            server.send(message)
            ciphertext = server.recv(1024)
            server.close()
            
            # Compare ciphertext blocks to verify the guess
            # If blocks 1 and 2 are identical, our guess is correct
            if len(ciphertext) >= 48 and ciphertext[16:32] == ciphertext[32:48]:
                print(f"✓ Found first character: '{guess}'")
                return guess
                
        except Exception as e:
            print(f"Error testing character '{guess}': {e}")
            continue
    
    print("⚠ Failed to discover first character")
    return None

def discover_complete_secret():
    """
    Discover the entire secret using the full ACP attack.
    
    This function implements the complete attack that discovers all characters
    of the secret by carefully managing block alignment and padding.
    
    Returns:
        bytes: The complete discovered secret
    """
    print("\n=== Discovering Complete Secret ===")
    
    # Initialize attack variables
    secret = b''
    postfix = b' - and the sec:'
    
    # Discover each character of the secret (assuming 16-byte secret)
    for i in range(AES.block_size):
        print(f"\nDiscovering character {i+1}/{AES.block_size}...")
        
        # Create padding to align the secret character at the end of a block
        padding = (AES.block_size - i) * b'A'
        
        # Try each printable character
        for guess in string.printable:
            # Construct the attack message
            message = postfix + secret + guess.encode() + padding
            
            try:
                # Connect to the encryption oracle
                server = remote(HOST, PORT)
                server.send(message)
                ciphertext = server.recv(1024)
                server.close()
                
                # Compare ciphertext blocks to verify the guess
                if len(ciphertext) >= 64 and ciphertext[16:32] == ciphertext[48:64]:
                    print(f"✓ Found character {i+1}: '{guess}'")
                    secret += guess.encode()
                    
                    # Adjust postfix for next iteration
                    postfix = postfix[1:] if len(postfix) > 0 else b''
                    break
                    
            except Exception as e:
                print(f"Error testing character '{guess}': {e}")
                continue
        else:
            print(f"⚠ Failed to discover character {i+1}")
            break
    
    return secret

def main():
    """Main function that demonstrates the complete ACP attack tutorial."""
    print("=== AES-ECB Adaptive Chosen-Plaintext Attack Tutorial ===")
    print("This tutorial demonstrates how to exploit ECB mode's deterministic encryption")
    print("to discover a secret string through systematic input manipulation.\n")
    
    print("Oracle target:", f"{HOST}:{PORT}")
    
    # Step 1: Analyze message structure (educational)
    # Uncomment the following line to see detailed structure analysis
    # analyze_message_structure()
    
    # Step 2: Discover first character (basic demonstration)
    print("\n--- Step 1: Basic Character Discovery ---")
    first_char = discover_first_character()
    
    # Step 3: Discover complete secret (full attack)
    print("\n--- Step 2: Complete Secret Discovery ---")
    complete_secret = discover_complete_secret()
    
    # Display results
    print(f"\n=== Attack Results ===")
    print(f"First character discovered: '{first_char}'")
    print(f"Complete secret discovered: {complete_secret}")
    print(f"Secret as string: '{complete_secret.decode()}'")
    
    if len(complete_secret) == 16:
        print("✓ Full 16-byte secret successfully recovered!")
    else:
        print("⚠ Partial secret recovery - attack may need refinement")

if __name__ == '__main__':
    main()
