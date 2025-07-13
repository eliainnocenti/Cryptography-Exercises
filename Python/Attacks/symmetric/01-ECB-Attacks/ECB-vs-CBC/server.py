#!/usr/bin/env python3
"""
ECB vs CBC Mode Detection Challenge Server

This server demonstrates the difference between ECB and CBC encryption modes
by randomly selecting one of them for each connection. The server provides
a testing ground for mode detection attacks.

The server:
1. Randomly selects either ECB or CBC mode
2. Accepts plaintext input from clients
3. Formats the input with fixed prefix and suffix
4. Encrypts the formatted message using the selected mode
5. Returns the ciphertext to the client

Educational Purpose:
This server helps understand the vulnerability of ECB mode by showing how
identical plaintext blocks produce different results in ECB vs CBC modes.

Usage:
    python3 server.py
"""

import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

from mysecrets import ecb_oracle_key
from myconfig import HOST, PORT

# Constants to represent encryption modes
ECB_MODE = 0
CBC_MODE = 1

def encrypt_message(message, mode, key):
    """
    Encrypt a message using the specified mode (ECB or CBC).
    
    Args:
        message (str): The plaintext message to encrypt
        mode (int): The encryption mode (ECB_MODE or CBC_MODE)
        key (bytes): The encryption key
        
    Returns:
        bytes: The encrypted ciphertext
    """
    # Pad the message to match AES block size
    padded_message = pad(message.encode(), AES.block_size)
    
    # Create cipher based on the selected mode
    if mode == ECB_MODE:
        cipher = AES.new(key, AES.MODE_ECB)
        print("Using ECB mode - identical blocks will produce identical ciphertext")
    else:
        cipher = AES.new(key, AES.MODE_CBC)
        print("Using CBC mode - chaining will make identical blocks produce different ciphertext")
    
    # Encrypt the padded message
    ciphertext = cipher.encrypt(padded_message)
    
    return ciphertext

def format_message(user_input):
    """
    Format the user input with fixed prefix and suffix.
    
    This formatting creates a predictable structure that can be exploited
    for mode detection attacks.
    
    Args:
        user_input (str): The input received from the client
        
    Returns:
        str: The formatted message
    """
    prefix = "This is what I received: "
    suffix = " -- END OF MESSAGE"
    
    formatted_message = prefix + user_input + suffix
    
    print(f"Message structure:")
    print(f"  Prefix: '{prefix}' ({len(prefix)} bytes)")
    print(f"  User input: '{user_input}' ({len(user_input)} bytes)")
    print(f"  Suffix: '{suffix}' ({len(suffix)} bytes)")
    print(f"  Total: '{formatted_message}' ({len(formatted_message)} bytes)")
    
    return formatted_message

def main():
    """Main server function that handles mode detection challenge requests."""
    print("=== ECB vs CBC Mode Detection Challenge Server ===")
    print("This server randomly selects ECB or CBC mode for each connection.")
    print("Clients can send crafted inputs to detect which mode is being used.\n")
    
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    # Bind the socket to the specified host and port
    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Start listening for incoming connections
    s.listen(10)
    print(f'Socket now listening on {HOST}:{PORT}')

    try:
        # Main server loop to handle incoming connections
        while True:
            conn, addr = s.accept()
            print(f'\nNew mode detection challenge from {addr[0]}:{addr[1]}')

            try:
                # Randomly select encryption mode (ECB or CBC)
                selected_mode = getrandbits(1)
                
                print(f"Randomly selected mode: ", end='')
                if selected_mode == ECB_MODE:
                    print("ECB")
                else:
                    print("CBC")

                # Receive plaintext input from the client
                user_input = conn.recv(1024).decode()
                print(f"Received input: '{user_input}' ({len(user_input)} bytes)")

                # Format the message with fixed prefix and suffix
                message = format_message(user_input)

                # Encrypt the message using the selected mode
                ciphertext = encrypt_message(message, selected_mode, ecb_oracle_key)
                
                print(f"Encrypted message: {ciphertext.hex()}")
                print(f"Ciphertext length: {len(ciphertext)} bytes")

                # Send the ciphertext back to the client
                conn.send(ciphertext)
                
                print("Challenge completed - ciphertext sent to client")

            except Exception as e:
                print(f"Error processing request: {e}")
            finally:
                conn.close()

    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        s.close()

if __name__ == '__main__':
    main()
