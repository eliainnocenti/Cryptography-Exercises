#!/usr/bin/env python3
"""
CBC Bit-Flipping Attack Vulnerable Server

This server demonstrates a vulnerability in CBC mode encryption when used for
authentication tokens. The server generates encrypted cookies containing user
privileges and validates them later, but it's vulnerable to bit-flipping attacks.

The vulnerability exists because:
1. CBC mode allows targeted bit manipulation in the previous block
2. The server doesn't use proper authentication (MAC/signature)
3. Attackers can flip bits to change 'admin=0' to 'admin=1'

Process:
1. Client sends username, server generates encrypted cookie with 'admin=0'
2. Server sends encrypted cookie back to client
3. Client can manipulate cookie bits and send it back
4. Server decrypts and checks for 'admin=1' to grant admin access

Usage:
    python3 bf_server_cbc.py
"""

import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

from mysecrets import bf_key, bf_iv
from myconfig import HOST, PORT

def create_user_cookie(username):
    """
    Create a user cookie with admin privileges set to 0.
    
    Args:
        username (bytes): The username to include in the cookie
        
    Returns:
        bytes: The plaintext cookie before encryption
    """
    # Create cookie in format: username=<username>,admin=0
    cookie = b'username=' + username + b',admin=0'
    print(f"Created cookie: {cookie}")
    return cookie

def encrypt_cookie(cookie, key, iv):
    """
    Encrypt a cookie using AES-CBC mode.
    
    Args:
        cookie (bytes): The plaintext cookie to encrypt
        key (bytes): The encryption key
        iv (bytes): The initialization vector
        
    Returns:
        bytes: The encrypted cookie
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_cookie = pad(cookie, AES.block_size)
    
    print(f"Padded cookie: {padded_cookie}")
    print(f"Padded cookie length: {len(padded_cookie)} bytes")
    
    # Show block structure for educational purposes
    for i in range(0, len(padded_cookie), AES.block_size):
        block = padded_cookie[i:i+AES.block_size]
        print(f"Block {i//AES.block_size}: {block}")
    
    ciphertext = cipher.encrypt(padded_cookie)
    print(f"Encrypted cookie: {ciphertext.hex()}")
    
    return ciphertext

def decrypt_cookie(encrypted_cookie, key, iv):
    """
    Decrypt an encrypted cookie using AES-CBC mode.
    
    Args:
        encrypted_cookie (bytes): The encrypted cookie to decrypt
        key (bytes): The decryption key
        iv (bytes): The initialization vector
        
    Returns:
        bytes: The decrypted cookie, or None if decryption fails
    """
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_cookie)
        unpadded = unpad(decrypted, AES.block_size)
        
        print(f"Decrypted cookie: {unpadded}")
        return unpadded
        
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def check_admin_privileges(cookie):
    """
    Check if the decrypted cookie grants admin privileges.
    
    Args:
        cookie (bytes): The decrypted cookie to check
        
    Returns:
        tuple: (is_admin, response_message)
    """
    if b'admin=1' in cookie:
        print("✓ Admin privileges detected!")
        return True, "You are an admin!"
    else:
        # Extract username for regular users
        try:
            username_start = cookie.index(b'=') + 1
            username_end = cookie.index(b',')
            username = cookie[username_start:username_end].decode('utf-8')
            
            message = f"Welcome {username}! You are a normal user."
            print(f"Regular user access: {message}")
            return False, message
            
        except Exception as e:
            print(f"Error parsing cookie: {e}")
            return False, "Welcome! You are a normal user."

def main():
    """Main server function that handles bit-flipping attack scenarios."""
    print("=== CBC Bit-Flipping Attack Vulnerable Server ===")
    print("This server demonstrates vulnerability to bit-flipping attacks in CBC mode.")
    print("WARNING: This implementation is intentionally vulnerable for educational purposes!\n")
    
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    s.listen(10)
    print(f'Socket now listening on {HOST}:{PORT}')

    try:
        while True:
            conn, addr = s.accept()
            print(f"\nBit flipping server. Connection from {addr[0]}:{addr[1]}")

            try:
                # Phase 1: Generate and send encrypted cookie
                print("\n--- Phase 1: Cookie Generation ---")
                
                # Receive username from client
                username = conn.recv(1024)
                print(f"Received username: {username}")

                # Create user cookie with admin=0
                cookie = create_user_cookie(username)

                # Encrypt the cookie
                encrypted_cookie = encrypt_cookie(cookie, bf_key, bf_iv)

                # Send encrypted cookie to client
                conn.send(encrypted_cookie)
                print("Cookie sent to client.")

                # Phase 2: Receive and validate modified cookie
                print("\n--- Phase 2: Cookie Validation ---")
                
                # Receive potentially modified cookie from client
                received_cookie = conn.recv(1024)
                print(f"Received cookie for validation: {received_cookie.hex()}")

                # Decrypt the received cookie
                decrypted_cookie = decrypt_cookie(received_cookie, bf_key, bf_iv)

                if decrypted_cookie is None:
                    # Decryption failed
                    response = "Invalid cookie - authentication failed"
                    print(f"Authentication failed: {response}")
                    conn.send(response.encode())
                else:
                    # Check admin privileges
                    is_admin, response = check_admin_privileges(decrypted_cookie)
                    
                    # Send response to client
                    conn.send(response.encode())
                    
                    if is_admin:
                        print("⚠ SECURITY ALERT: Admin access granted! Possible bit-flipping attack.")
                    else:
                        print("✓ Regular user authenticated successfully.")

            except Exception as e:
                print(f"Error processing connection: {e}")
                try:
                    conn.send(b'Server error occurred')
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
