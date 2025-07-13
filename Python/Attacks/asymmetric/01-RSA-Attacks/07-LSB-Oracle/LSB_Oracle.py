#!/usr/bin/env python3
"""
LSB Oracle Server - RSA Least Significant Bit Oracle Attack

This module implements a vulnerable RSA server that leaks the least significant bit (LSB) 
of decrypted ciphertexts, enabling an LSB Oracle attack.

ATTACK OVERVIEW:
The LSB Oracle attack exploits the multiplicative property of RSA encryption and the 
ability to determine the parity (odd/even) of the plaintext through the LSB of the 
decrypted message. By repeatedly multiplying the ciphertext by 2^e and querying the 
oracle for the LSB, an attacker can perform a binary search to recover the plaintext.

MATHEMATICAL FOUNDATION:
- RSA property: (c * 2^e) mod n = (m * 2) mod n
- LSB reveals parity: LSB = 1 if odd, LSB = 0 if even
- Binary search: Each query halves the search space for the plaintext

VULNERABILITY:
This server demonstrates a critical vulnerability where side-channel information 
(the LSB) is leaked during decryption, allowing complete plaintext recovery.

SECURITY LESSONS:
1. Never leak partial information about plaintexts
2. Use proper padding schemes (OAEP) to prevent chosen ciphertext attacks
3. Implement constant-time operations to prevent timing attacks
4. Use authenticated encryption for data integrity
"""

import socket
import sys
import logging
from typing import Optional, Tuple

from myconfig import HOST, PORT
from mysecrets import lsb_d as d, lsb_n as n

# Configure logging for better debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LSBOracle:
    """
    LSB Oracle Server - A vulnerable RSA server that leaks the LSB of decrypted ciphertexts.
    
    This server demonstrates the LSB Oracle attack vulnerability by providing an oracle
    that reveals the least significant bit of RSA-decrypted messages.
    """
    
    def __init__(self, host: str = HOST, port: int = PORT):
        """
        Initialize the LSB Oracle server.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
        """
        self.host = host
        self.port = port
        self.private_key_d = d
        self.modulus_n = n
        self.socket = None
        
    def create_socket(self) -> bool:
        """
        Create and configure the server socket.
        
        Returns:
            bool: True if socket creation successful, False otherwise
        """
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.info('Socket created successfully')
            return True
        except socket.error as e:
            logger.error(f'Socket creation failed: {e}')
            return False
            
    def bind_socket(self) -> bool:
        """
        Bind the socket to the specified host and port.
        
        Returns:
            bool: True if binding successful, False otherwise
        """
        try:
            self.socket.bind((self.host, self.port))
            logger.info(f'Socket bound to {self.host}:{self.port}')
            return True
        except socket.error as e:
            logger.error(f'Socket bind failed: {e}')
            return False
            
    def decrypt_and_get_lsb(self, ciphertext: int) -> int:
        """
        Decrypt the ciphertext and return its least significant bit.
        
        This is the vulnerable oracle function that leaks the LSB of the plaintext.
        
        Args:
            ciphertext: RSA ciphertext as integer
            
        Returns:
            int: LSB of the decrypted plaintext (0 or 1)
        """
        # Perform RSA decryption: m = c^d mod n
        plaintext = pow(ciphertext, self.private_key_d, self.modulus_n)
        
        # Extract the least significant bit (parity)
        lsb = plaintext % 2
        
        logger.info(f'Decrypted ciphertext, LSB: {lsb}')
        return lsb
        
    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """
        Handle a client connection and process the LSB oracle query.
        
        Args:
            conn: Client connection socket
            addr: Client address tuple (host, port)
        """
        try:
            logger.info(f'New RSA encrypted message received from {addr[0]}:{addr[1]}')
            
            # Receive the ciphertext from the client
            ciphertext_bytes = conn.recv(4096)
            if not ciphertext_bytes:
                logger.warning('No data received from client')
                return
                
            # Convert bytes to integer (big-endian)
            ciphertext = int.from_bytes(ciphertext_bytes, byteorder='big')
            logger.info(f'Received ciphertext: {ciphertext}')
            
            # Decrypt and get the LSB (vulnerable oracle operation)
            lsb = self.decrypt_and_get_lsb(ciphertext)
            
            # Send the LSB back to the client
            conn.send(int.to_bytes(lsb, 1, byteorder='big'))
            logger.info(f'Sent LSB: {lsb}')
            
        except Exception as e:
            logger.error(f'Error handling client {addr}: {e}')
        finally:
            conn.close()
            
    def start_server(self) -> None:
        """
        Start the LSB Oracle server and listen for connections.
        
        This method runs the main server loop, accepting connections and
        processing LSB oracle queries.
        """
        if not self.create_socket():
            sys.exit(1)
            
        if not self.bind_socket():
            sys.exit(1)
            
        try:
            # Listen for connections (maximum 10 in queue)
            self.socket.listen(10)
            logger.info('LSB Oracle server listening for connections...')
            
            # Main server loop
            while True:
                try:
                    # Accept client connection (blocking call)
                    conn, addr = self.socket.accept()
                    self.handle_client(conn, addr)
                    
                except KeyboardInterrupt:
                    logger.info('Server shutdown requested')
                    break
                except Exception as e:
                    logger.error(f'Error accepting connection: {e}')
                    
        finally:
            self.close_server()
            
    def close_server(self) -> None:
        """Close the server socket and cleanup resources."""
        if self.socket:
            self.socket.close()
            logger.info('Server socket closed')

def main():
    """
    Main function to start the LSB Oracle server.
    
    This function demonstrates the vulnerable RSA server that leaks the LSB
    of decrypted ciphertexts, enabling the LSB Oracle attack.
    """
    print("=" * 60)
    print("LSB ORACLE SERVER - CRYPTOGRAPHIC VULNERABILITY DEMO")
    print("=" * 60)
    print()
    print("This server demonstrates the LSB Oracle attack vulnerability.")
    print("It leaks the least significant bit of RSA-decrypted messages.")
    print()
    print("SECURITY WARNING: This is a vulnerable implementation!")
    print("Never leak partial plaintext information in production!")
    print()
    print("Starting LSB Oracle server...")
    print("Press Ctrl+C to stop the server")
    print()
    
    # Create and start the LSB Oracle server
    oracle = LSBOracle()
    oracle.start_server()

if __name__ == '__main__':
    main()
