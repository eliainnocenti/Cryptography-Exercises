#!/usr/bin/env python3
"""
ECB Cookie Generation Server

This server generates encrypted user profile cookies using AES-ECB mode.
The server is vulnerable to copy-and-paste attacks due to ECB's deterministic
encryption behavior, which allows attackers to manipulate encrypted blocks.

The server:
1. Accepts email addresses from clients
2. Generates user profiles with default "user" role
3. Encodes profiles as key-value pairs
4. Encrypts profiles using AES-ECB mode
5. Returns encrypted cookies to clients

Security Vulnerability:
ECB mode encrypts identical plaintext blocks to identical ciphertext blocks,
enabling attackers to copy and paste blocks to forge admin cookies.

Usage:
    python3 copypaste_server_gencookie_service.py
"""

import sys
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from mysecrets import ecb_oracle_key as key
from myconfig import HOST, PORT

def profile_for(email):
    """
    Create a user profile dictionary from an email address.
    
    This function simulates a database access to create user profile data.
    It sanitizes the email by removing characters that could interfere with
    the encoding format.
    
    Args:
        email (str): The email address to create a profile for
        
    Returns:
        dict: A dictionary containing user profile information
    """
    # Sanitize email by removing characters that could break the encoding
    sanitized_email = email.replace('=', '').replace('&', '')
    
    # Create a standard user profile
    profile = {
        "email": sanitized_email,
        "UID": 10,
        "role": "user"  # Default role - this is what attackers want to change
    }
    
    return profile

def encode_profile(profile_dict):
    """
    Encode a profile dictionary into a key-value string format.
    
    The encoding format is: key1=value1&key2=value2&key3=value3
    This format is commonly used in web applications for storing user data.
    
    Args:
        profile_dict (dict): The profile dictionary to encode
        
    Returns:
        str: The encoded profile string
    """
    encoded_parts = []
    
    print(f"Encoding profile with {len(profile_dict.keys())} keys")
    
    # Convert each key-value pair to the encoded format
    for key, value in profile_dict.items():
        encoded_parts.append(f"{key}={value}")
    
    # Join all parts with '&' separator
    encoded_profile = "&".join(encoded_parts)
    
    print(f"Encoded profile: {encoded_profile}")
    return encoded_profile

def encrypt_profile(encoded_profile):
    """
    Encrypt a profile string using AES in ECB mode.
    
    This function demonstrates the vulnerability of ECB mode by encrypting
    the profile deterministically. Identical plaintext blocks will produce
    identical ciphertext blocks.
    
    Args:
        encoded_profile (str): The encoded profile string to encrypt
        
    Returns:
        bytes: The encrypted profile (ciphertext)
    """
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Pad the plaintext to match AES block size (16 bytes)
    plaintext = pad(encoded_profile.encode(), AES.block_size)
    
    print(f"Padded plaintext: {plaintext}")
    print(f"Plaintext length: {len(plaintext)} bytes")
    
    # Show block breakdown for educational purposes
    for i in range(0, len(plaintext), AES.block_size):
        block = plaintext[i:i+AES.block_size]
        print(f"Block {i//AES.block_size}: {block}")
    
    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(plaintext)
    
    return ciphertext

def decrypt_msg(ciphertext):
    """
    Decrypt a ciphertext using AES in ECB mode.
    
    This function is provided for debugging and verification purposes.
    It shows how the encrypted cookies can be decrypted back to plaintext.
    
    Args:
        ciphertext (bytes): The encrypted message to decrypt
        
    Returns:
        bytes: The decrypted plaintext (unpadded)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    
    # Remove padding to get the original plaintext
    return unpad(decrypted, AES.block_size)

def main():
    """Main server function that handles cookie generation requests."""
    print("=== ECB Cookie Generation Server ===")
    print("This server generates encrypted user profile cookies using AES-ECB mode.")
    print("WARNING: ECB mode is vulnerable to copy-and-paste attacks!\n")
    
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
            print(f'Cookie generation request from {addr[0]}:{addr[1]}')

            try:
                # Receive the email from the client
                email_bytes = conn.recv(1024)
                email = email_bytes.decode()
                print(f"Received email: {email}")

                # Generate user profile from email
                profile = profile_for(email)
                print(f"Generated profile: {profile}")

                # Encode the profile to string format
                encoded_profile = encode_profile(profile)

                # Encrypt the encoded profile
                encrypted_cookie = encrypt_profile(encoded_profile)
                print(f"Encrypted cookie: {encrypted_cookie.hex()}")

                # Send the encrypted cookie back to the client
                conn.send(encrypted_cookie)
                
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
