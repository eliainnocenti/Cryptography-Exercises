#!/usr/bin/env python3
"""
AES-ECB Adaptive Chosen-Plaintext Attack (ACP) Client

This client demonstrates an Adaptive Chosen-Plaintext Attack against an ECB
encryption oracle. The attack exploits the deterministic nature of ECB mode
to discover a secret string by carefully crafting input messages.

The attack works by:
1. Controlling the input to align the secret at block boundaries
2. Comparing ciphertext blocks to identify when a guess is correct
3. Building the secret character by character

Attack Strategy:
- The oracle encrypts: "Here is the msg:{input} - and the sec:{secret}"
- By controlling the input, we can align blocks to compare ciphertext patterns
- ECB mode encrypts identical blocks to identical ciphertext, revealing the secret

Usage:
    python3 ACP_attack_client.py
"""

import string
import os

# Configure pwntools to suppress unnecessary output
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES
from myconfig import HOST, PORT

def discover_secret():
    """
    Discover the secret string using Adaptive Chosen-Plaintext Attack.
    
    The attack exploits ECB mode's deterministic encryption by comparing
    ciphertext blocks to identify correct character guesses.
    
    Returns:
        str: The discovered secret string
    """
    SECRET_LEN = 16  # Length of the secret string to be discovered
    secret = ""      # Variable to store the discovered secret
    
    # Block structure analysis:
    # Block 0 (0-15):   "Here is the msg"
    # Block 1 (16-31):  "{input}" (controlled by attacker)
    # Block 2 (32-47):  "{input_overflow} - and the sec:" (partially controlled)
    # Block 3 (48-63):  "{secret_chars}" (target to discover)
    
    # The fixed part of the message that precedes the secret
    fixed_prefix = " - and the sec:"
    
    print(f"Starting ACP attack to discover {SECRET_LEN}-character secret...")
    print(f"Target oracle: {HOST}:{PORT}")
    
    # Loop through each character position in the secret
    for i in range(SECRET_LEN):
        print(f"\nDiscovering character {i+1}/{SECRET_LEN}...")
        
        # Create padding to align the secret character at the end of a block
        # This ensures the target character appears at a predictable position
        padding = "A" * (AES.block_size - i - 1)
        
        # Try each printable character as a potential secret character
        for candidate_char in string.printable:
            try:
                # Connect to the encryption oracle
                server = remote(HOST, PORT)
                
                # Construct the message with the guessed character
                # The goal is to make two blocks identical when the guess is correct
                test_input = fixed_prefix + secret + candidate_char + padding
                
                print(f"Testing character: '{candidate_char}' with input: '{test_input}'")
                
                # Send the crafted input to the oracle
                server.send(test_input.encode())
                
                # Receive the ciphertext from the oracle
                ciphertext = server.recv(1024)
                server.close()
                
                # Compare relevant ciphertext blocks to check if the guess is correct
                # If blocks are identical, we've found the correct character
                if len(ciphertext) >= 64 and ciphertext[16:32] == ciphertext[48:64]:
                    print(f"✓ Found character {i+1}: '{candidate_char}'")
                    secret += candidate_char
                    
                    # Adjust the fixed part to maintain alignment for next character
                    fixed_prefix = fixed_prefix[1:] if len(fixed_prefix) > 0 else ""
                    break
                    
            except Exception as e:
                print(f"Error testing character '{candidate_char}': {e}")
                continue
        else:
            # If no character was found, something went wrong
            print(f"Failed to discover character {i+1}")
            break
    
    return secret

def main():
    """Main function to execute the ACP attack."""
    print("=== AES-ECB Adaptive Chosen-Plaintext Attack ===")
    print("This attack exploits ECB mode's deterministic encryption")
    print("to discover a secret string through careful input manipulation.\n")
    
    # Execute the attack
    discovered_secret = discover_secret()
    
    print(f"\n=== Attack Results ===")
    print(f"Secret discovered: '{discovered_secret}'")
    print(f"Length: {len(discovered_secret)} characters")
    
    if len(discovered_secret) == 16:
        print("✓ Full secret successfully recovered!")
    else:
        print("⚠ Partial secret recovery - attack may need refinement")

if __name__ == '__main__':
    main()
