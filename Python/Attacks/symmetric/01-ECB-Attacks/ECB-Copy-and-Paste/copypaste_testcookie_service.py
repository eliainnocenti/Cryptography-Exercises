#!/usr/bin/env python3
"""
ECB Cookie Authentication Test Server

This server authenticates users by validating encrypted cookies and checking
their role privileges. The server is vulnerable to forged admin cookies
created through ECB copy-and-paste attacks.

The server:
1. Accepts encrypted cookies from clients
2. Decrypts cookies using AES-ECB mode
3. Parses the decrypted profile data
4. Grants admin or user access based on the role field

Security Vulnerability:
Since the server uses ECB mode, attackers can forge admin cookies by
copying and pasting ciphertext blocks from different encrypted profiles.

Usage:
    python3 copypaste_testcookie_service.py
"""

import sys
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from mysecrets import ecb_oracle_key as key
from myconfig import HOST, PORT, DELTA_PORT

def profile_for(email):
    """
    Create a user profile dictionary from an email address.
    
    This function is included for consistency with the cookie generation server
    but is not directly used in the authentication process.
    
    Args:
        email (str): The email address to create a profile for
        
    Returns:
        dict: A dictionary containing user profile information
    """
    # Sanitize email by removing characters that could break the encoding
    sanitized_email = email.replace('=', '').replace('&', '')
    
    profile = {
        "email": sanitized_email,
        "UID": 10,
        "role": "user"
    }
    
    return profile

def encode_profile(profile_dict):
    """
    Encode a profile dictionary into a key-value string format.
    
    Args:
        profile_dict (dict): The profile dictionary to encode
        
    Returns:
        str: The encoded profile string
    """
    encoded_parts = []
    
    print(f"Encoding profile with {len(profile_dict.keys())} keys")
    
    for key, value in profile_dict.items():
        encoded_parts.append(f"{key}={value}")
    
    encoded_profile = "&".join(encoded_parts)
    return encoded_profile

def encrypt_profile(encoded_profile):
    """
    Encrypt a profile string using AES in ECB mode.
    
    Args:
        encoded_profile (str): The encoded profile string to encrypt
        
    Returns:
        bytes: The encrypted profile (ciphertext)
    """
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(), AES.block_size)
    print(f"Padded plaintext: {plaintext}")
    return cipher.encrypt(plaintext)

def decrypt_cookie(ciphertext):
    """
    Decrypt an encrypted cookie using AES in ECB mode.
    
    Args:
        ciphertext (bytes): The encrypted cookie to decrypt
        
    Returns:
        bytes: The decrypted cookie data, or None if decryption fails
    """
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, AES.block_size)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None

def authenticate_user(decrypted_cookie):
    """
    Authenticate a user based on their decrypted cookie data.
    
    Args:
        decrypted_cookie (bytes): The decrypted cookie data
        
    Returns:
        tuple: (is_admin, response_message)
    """
    print(f"Authenticating user with cookie: {decrypted_cookie}")
    
    # Check if the user has admin privileges
    if b'role=admin' in decrypted_cookie:
        print("✓ Admin access granted!")
        return True, "You are an admin!"
    else:
        # Extract user information for regular users
        try:
            # Find the email field in the cookie
            cookie_str = decrypted_cookie.decode('utf-8')
            
            # Parse the cookie to extract email (basic parsing)
            if '=' in cookie_str:
                parts = cookie_str.split('&')
                email_part = next((part for part in parts if part.startswith('email=')), None)
                
                if email_part:
                    email = email_part.split('=')[1]
                    message = f"Welcome {email}! You are a normal user."
                else:
                    message = "Welcome! You are a normal user."
            else:
                message = "Welcome! You are a normal user."
                
            print(f"Regular user access: {message}")
            return False, message
            
        except Exception as e:
            print(f"Error parsing cookie: {e}")
            return False, "Welcome! You are a normal user."

def main():
    """Main server function that handles cookie authentication requests."""
    print("=== ECB Cookie Authentication Test Server ===")
    print("This server validates encrypted cookies and checks user privileges.")
    print("WARNING: Vulnerable to forged admin cookies due to ECB mode!\n")
    
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    # Bind the socket to the specified host and port (with delta offset)
    try:
        s.bind((HOST, PORT + DELTA_PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Start listening for incoming connections
    s.listen(10)
    print(f'Socket now listening on {HOST}:{PORT + DELTA_PORT}')

    try:
        # Main server loop to handle incoming connections
        while True:
            conn, addr = s.accept()
            print(f'Cookie authentication request from {addr[0]}:{addr[1]}')

            try:
                # Receive the encrypted cookie from the client
                received_cookie = conn.recv(1024)
                print(f"Received encrypted cookie: {received_cookie.hex()}")

                # Decrypt the cookie
                decrypted_cookie = decrypt_cookie(received_cookie)
                
                if decrypted_cookie is None:
                    # Decryption failed (wrong padding or invalid data)
                    response = "Invalid cookie - authentication failed"
                    print(f"Authentication failed: {response}")
                    conn.send(response.encode())
                else:
                    # Authenticate the user based on the decrypted cookie
                    is_admin, response = authenticate_user(decrypted_cookie)
                    
                    # Send the authentication response
                    conn.send(response.encode())
                    
                    if is_admin:
                        print("⚠ SECURITY ALERT: Admin access granted! Possible forged cookie.")
                    else:
                        print("✓ Regular user authenticated successfully.")
                        
            except Exception as e:
                print(f"Error processing authentication request: {e}")
                try:
                    conn.send("Authentication error".encode())
                except:
                    pass
            finally:
                conn.close()

    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        s.close()

if __name__ == '__main__':
    main()
