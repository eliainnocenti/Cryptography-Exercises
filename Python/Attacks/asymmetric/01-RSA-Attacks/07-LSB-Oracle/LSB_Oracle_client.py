#!/usr/bin/env python3
"""
LSB Oracle Client - RSA Least Significant Bit Oracle Attack Implementation

This module implements the client-side LSB Oracle attack against RSA encryption.
The attack exploits the multiplicative property of RSA and the ability to determine
the parity of the plaintext through an LSB oracle.

ATTACK METHODOLOGY:
1. Start with bounds: [0, n) where n is the RSA modulus
2. For each iteration i:
   - Multiply ciphertext by 2^e: c' = (c * 2^e) mod n
   - Query oracle for LSB of decrypted c'
   - If LSB = 1: plaintext is in upper half, update lower_bound
   - If LSB = 0: plaintext is in lower half, update upper_bound
3. Repeat until bounds converge to the plaintext

MATHEMATICAL FOUNDATION:
- RSA property: (c * 2^e) mod n = (m * 2) mod n
- Binary search: Each query halves the search space
- Convergence: After ~log2(n) queries, bounds converge to plaintext

SECURITY IMPACT:
This attack demonstrates how leaking even a single bit of information
can lead to complete plaintext recovery in RSA systems.
"""

import os
import logging
from typing import Tuple, Optional

# Configure pwntools to work in IDE environments
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwnlib.tubes.remote import remote

from myconfig import HOST, PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LSBOracleClient:
    """
    LSB Oracle Attack Client - Implements the client-side LSB Oracle attack.
    
    This client performs a binary search attack against an RSA LSB oracle,
    recovering the plaintext by exploiting leaked LSB information.
    """
    
    def __init__(self, host: str = HOST, port: int = PORT):
        """
        Initialize the LSB Oracle client.
        
        Args:
            host: Oracle server hostname or IP address
            port: Oracle server port number
        """
        self.host = host
        self.port = port
        self.modulus_n = n
        self.public_exponent_e = e
        self.target_ciphertext = ciphertext
        
    def to_bytes(self, value: int, length: Optional[int] = None) -> bytes:
        """
        Convert integer to bytes with specified length.
        
        Args:
            value: Integer value to convert
            length: Byte length (defaults to modulus bit length)
            
        Returns:
            bytes: Big-endian byte representation
        """
        if length is None:
            length = (self.modulus_n.bit_length() + 7) // 8
        return int.to_bytes(value, length, byteorder='big')
        
    def to_int(self, data: bytes) -> int:
        """
        Convert bytes to integer.
        
        Args:
            data: Byte data to convert
            
        Returns:
            int: Integer representation
        """
        return int.from_bytes(data, byteorder='big')
        
    def print_bounds(self, lower: int, upper: int) -> None:
        """
        Print current search bounds.
        
        Args:
            lower: Lower bound of search space
            upper: Upper bound of search space
        """
        logger.info(f"Current bounds: [{lower}, {upper}]")
        
    def query_oracle(self, ciphertext_query: int) -> int:
        """
        Query the LSB oracle with a ciphertext and return the LSB.
        
        Args:
            ciphertext_query: Ciphertext to query the oracle with
            
        Returns:
            int: LSB of the decrypted plaintext (0 or 1)
            
        Raises:
            Exception: If communication with oracle fails
        """
        try:
            # Connect to the oracle server
            server = remote(self.host, self.port)
            
            # Send the ciphertext query
            server.send(self.to_bytes(ciphertext_query))
            
            # Receive the LSB response
            response = server.recv(1024)
            server.close()
            
            if not response:
                raise Exception("No response from oracle")
                
            lsb = response[0]
            logger.debug(f"Oracle query - Ciphertext: {ciphertext_query}, LSB: {lsb}")
            
            return lsb
            
        except Exception as e:
            logger.error(f"Oracle query failed: {e}")
            raise
            
    def test_oracle_connection(self) -> bool:
        """
        Test the connection to the oracle server.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            logger.info("Testing oracle connection...")
            lsb = self.query_oracle(self.target_ciphertext)
            logger.info(f"Oracle connection successful. Initial LSB: {lsb}")
            return True
        except Exception as e:
            logger.error(f"Oracle connection test failed: {e}")
            return False
            
    def perform_lsb_attack(self) -> Tuple[int, int]:
        """
        Perform the LSB Oracle attack to recover the plaintext.
        
        This method implements the core binary search algorithm that exploits
        the LSB oracle to recover the plaintext by repeatedly narrowing the
        search bounds.
        
        Returns:
            Tuple[int, int]: Final (lower_bound, upper_bound) containing the plaintext
        """
        logger.info("Starting LSB Oracle attack...")
        logger.info(f"Target ciphertext: {self.target_ciphertext}")
        logger.info(f"Modulus bit length: {self.modulus_n.bit_length()}")
        
        # Initialize search bounds: plaintext is in [0, n)
        upper_bound = self.modulus_n
        lower_bound = 0
        
        logger.info("Initial bounds:")
        self.print_bounds(lower_bound, upper_bound)
        
        # Current ciphertext for queries
        current_ciphertext = self.target_ciphertext
        
        # Perform binary search using LSB oracle
        for iteration in range(self.modulus_n.bit_length()):
            logger.info(f"\n--- Iteration {iteration + 1} ---")
            
            # Multiply ciphertext by 2^e to double the plaintext
            # This uses the multiplicative property of RSA:
            # (c * 2^e) mod n = (m * 2) mod n
            current_ciphertext = (pow(2, self.public_exponent_e, self.modulus_n) * current_ciphertext) % self.modulus_n
            
            # Query the oracle for the LSB of the doubled plaintext
            lsb = self.query_oracle(current_ciphertext)
            logger.info(f"LSB of doubled plaintext: {lsb}")
            
            # Update bounds based on LSB (binary search)
            if lsb == 1:
                # Plaintext is odd, so it's in the upper half
                lower_bound = (upper_bound + lower_bound) // 2
                logger.info("Plaintext is odd - updating lower bound")
            else:
                # Plaintext is even, so it's in the lower half
                upper_bound = (upper_bound + lower_bound) // 2
                logger.info("Plaintext is even - updating upper bound")
                
            # Print current bounds
            self.print_bounds(lower_bound, upper_bound)
            
            # Check if bounds have converged
            if upper_bound - lower_bound <= 1:
                logger.info("Bounds converged!")
                break
                
        return lower_bound, upper_bound
        
    def decode_result(self, lower_bound: int, upper_bound: int) -> Optional[str]:
        """
        Attempt to decode the recovered plaintext as a string.
        
        Args:
            lower_bound: Lower bound of the recovered plaintext
            upper_bound: Upper bound of the recovered plaintext
            
        Returns:
            Optional[str]: Decoded string if successful, None otherwise
        """
        try:
            # Try to decode the lower bound as the plaintext
            plaintext_bytes = self.to_bytes(lower_bound)
            
            # Remove leading zero bytes and attempt to decode
            plaintext_bytes = plaintext_bytes.lstrip(b'\x00')
            decoded = plaintext_bytes.decode('utf-8', errors='ignore')
            
            logger.info(f"Decoded plaintext: '{decoded}'")
            return decoded
            
        except Exception as e:
            logger.error(f"Failed to decode plaintext: {e}")
            return None
            
    def run_attack(self) -> None:
        """
        Run the complete LSB Oracle attack.
        
        This method orchestrates the entire attack process:
        1. Test oracle connection
        2. Perform the LSB attack
        3. Decode and display results
        """
        print("=" * 60)
        print("LSB ORACLE ATTACK - RSA PLAINTEXT RECOVERY")
        print("=" * 60)
        print()
        print("This attack exploits an RSA LSB oracle to recover plaintext")
        print("using a binary search technique.")
        print()
        
        # Test oracle connection
        if not self.test_oracle_connection():
            print("Failed to connect to oracle server!")
            return
            
        print("Oracle connection successful. Starting attack...")
        print()
        
        # Perform the LSB attack
        try:
            lower_bound, upper_bound = self.perform_lsb_attack()
            
            print("\n" + "=" * 60)
            print("ATTACK RESULTS")
            print("=" * 60)
            print(f"Final lower bound: {lower_bound}")
            print(f"Final upper bound: {upper_bound}")
            print(f"Plaintext (integer): {lower_bound}")
            
            # Attempt to decode as string
            decoded = self.decode_result(lower_bound, upper_bound)
            if decoded:
                print(f"Plaintext (string): '{decoded}'")
            else:
                print("Could not decode plaintext as string")
                
        except Exception as e:
            logger.error(f"Attack failed: {e}")
            print(f"Attack failed: {e}")

def main():
    """
    Main function to run the LSB Oracle attack.
    
    This function demonstrates the LSB Oracle attack against RSA encryption,
    showing how leaking even a single bit can lead to complete plaintext recovery.
    """
    client = LSBOracleClient()
    client.run_attack()

if __name__ == '__main__':
    main()
