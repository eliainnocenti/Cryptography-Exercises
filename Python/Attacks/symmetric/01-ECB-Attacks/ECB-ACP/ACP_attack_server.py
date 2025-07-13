#!/usr/bin/env python3
"""
AES-ECB Encryption Oracle Server

This server demonstrates an ECB encryption oracle that can be exploited using
the Adaptive Chosen-Plaintext Attack (ACP). The server accepts input strings
and encrypts them along with a secret using AES-ECB mode.

The vulnerability lies in the deterministic nature of ECB mode, which encrypts
identical plaintext blocks to identical ciphertext blocks, allowing attackers
to discover the secret through careful manipulation of the input.

Usage:
    python3 ACP_attack_server.py
"""

import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from mysecrets import ecb_oracle_key, ecb_oracle_secret
from myconfig import HOST, PORT

def main():
    """Main server function that handles ECB encryption oracle requests."""
    # Create a socket for the server
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
    print('Socket now listening')

    try:
        # Main loop to handle incoming connections
        while True:
            conn, addr = s.accept()  # Accept a new connection
            print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

            # Receive the input from the client
            input0 = conn.recv(1024).decode()
            
            # Construct the plaintext message with the secret
            # The secret is 16 bytes long, composed of printable characters
            # Format: "Here is the msg:{input} - and the sec:{secret}"
            message = """Here is the msg:{0} - and the sec:{1}""".format(input0, ecb_oracle_secret)
            
            # Pad the message to AES block size (16 bytes)
            padded_message = pad(message.encode(), AES.block_size)

            # Encrypt the message using AES in ECB mode
            # ECB mode encrypts each block independently, making it vulnerable to analysis
            cipher = AES.new(ecb_oracle_key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(padded_message)

            # Send the ciphertext back to the client
            conn.send(ciphertext)
            conn.close()  # Close the connection

    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        s.close()  # Close the server socket

if __name__ == '__main__':
    main()
