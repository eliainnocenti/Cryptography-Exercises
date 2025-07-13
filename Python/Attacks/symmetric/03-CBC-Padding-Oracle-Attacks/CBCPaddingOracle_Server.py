#!/usr/bin/env python3
"""
CBC Padding Oracle Attack Server

This server implements a vulnerable CBC padding oracle that can be exploited
to decrypt arbitrary ciphertexts without knowledge of the encryption key.

The server:
1. Receives an IV and ciphertext from clients
2. Attempts to decrypt the ciphertext using AES-CBC
3. Returns 'OK' if padding is valid, 'NO' if padding is invalid
4. This information leakage enables the padding oracle attack

Security Vulnerability:
The server reveals information about the plaintext through padding validation,
which allows an attacker to decrypt messages by systematically modifying
ciphertext blocks and observing the server's response.

Educational Purpose:
This demonstrates why cryptographic implementations must not leak information
about internal operations like padding validation.
"""

import socket
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from mysecrets import cbc_oracle_key as key
from myconfig import HOST, PORT


def create_padding_oracle_server():
    """
    Create and run the vulnerable CBC padding oracle server.
    
    The server listens for connections and provides padding validation
    services that leak information about the plaintext through timing
    or response differences.
    """
    # Create TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Listen for incoming connections
    s.listen(10)
    print('Socket now listening')

    # Main server loop - accept connections and process padding oracle requests
    while 1:
        conn, addr = s.accept()
        print('A new padding test requested by ' + addr[0] + ':' + str(addr[1]))

        try:
            # Receive IV from the client (16 bytes for AES)
            iv = conn.recv(AES.block_size)
            if len(iv) != AES.block_size:
                print("Invalid IV length received")
                conn.send(b'NO')
                conn.close()
                continue
            
            # Receive ciphertext from the client
            ciphertext = conn.recv(1024)
            if len(ciphertext) == 0:
                print("No ciphertext received")
                conn.send(b'NO')
                conn.close()
                continue

            # Initialize AES cipher in CBC mode with provided IV
            cipher = AES.new(key, AES.MODE_CBC, iv)

            try:
                # Attempt to decrypt and unpad the ciphertext
                # This is the vulnerable operation that leaks information
                plaintext = cipher.decrypt(ciphertext)
                unpad(plaintext, AES.block_size)
                
                # If we reach here, padding is valid
                # PKCS#7 padding: 01 / 0202 / 030303 / 04040404 / ...
                conn.send(b'OK')
                print("Valid padding detected")

            except ValueError as e:
                # Padding is invalid - this information leakage enables the attack
                conn.send(b'NO')
                print(f"Invalid padding detected: {e}")
                
        except Exception as e:
            print(f"Error processing request: {e}")
            conn.send(b'NO')
        
        finally:
            conn.close()

    s.close()


if __name__ == '__main__':
    print("=== CBC Padding Oracle Attack Server ===")
    print(f"Starting vulnerable server on {HOST}:{PORT}")
    print("WARNING: This server is intentionally vulnerable for educational purposes!")
    print("Press Ctrl+C to stop the server")
    
    try:
        create_padding_oracle_server()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Server error: {e}")
