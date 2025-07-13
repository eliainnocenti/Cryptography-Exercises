#!/usr/bin/env python3
"""
LSB Oracle Client (Decimal Precision) - Enhanced RSA LSB Oracle Attack

This module implements an enhanced version of the LSB Oracle attack using Python's
decimal module for arbitrary precision arithmetic. This approach provides better
numerical stability and accuracy for large RSA moduli.

IMPROVEMENTS OVER STANDARD VERSION:
- Uses decimal.Decimal for arbitrary precision floating-point arithmetic
- Provides more accurate intermediate results during binary search
- Better handles precision issues with very large RSA moduli
- Maintains numerical stability throughout the attack process

ATTACK METHODOLOGY:
Same as the standard LSB Oracle attack, but with enhanced precision:
1. Initialize bounds using Decimal arithmetic for high precision
2. Perform binary search with decimal division for exact midpoint calculation
3. Maintain precision throughout the attack to avoid rounding errors

WHEN TO USE THIS VERSION:
- Large RSA moduli (> 2048 bits) where precision matters
- Research scenarios requiring exact arithmetic
- When standard integer division introduces unacceptable errors
"""

import os
import logging
import decimal
from typing import Tuple, Optional

# Configure pwntools environment
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'

from pwnlib.tubes.remote import remote

from myconfig import HOST, PORT
from mysecrets import lsb_n as n, lsb_e as e
from mysecrets import lsb_ciphertext as ciphertext

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LSBOracleClientDecimal:
    """
    Enhanced LSB Oracle Attack Client using Decimal precision.
    
    This client performs the LSB Oracle attack with arbitrary precision arithmetic
    using Python's decimal module for improved accuracy with large RSA moduli.
    """
    
    def __init__(self, host: str = HOST, port: int = PORT):
        """
        Initialize the enhanced LSB Oracle client.
        
        Args:
            host: Oracle server hostname or IP address
            port: Oracle server port number
        """
        self.host = host
        self.port = port
        self.modulus_n = n
        self.public_exponent_e = e
        self.target_ciphertext = ciphertext
        
        # Configure decimal precision based on modulus bit length
        # Use extra precision to ensure accuracy throughout the attack
        precision = self.modulus_n.bit_length() + 50
        decimal.getcontext().prec = precision
        
        logger.info(f"Decimal precision set to {precision} digits")
        
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
        
    def print_bounds(self, lower: decimal.Decimal, upper: decimal.Decimal) -> None:
        """
        Print current search bounds with decimal precision.
        
        Args:
            lower: Lower bound of search space (Decimal)
            upper: Upper bound of search space (Decimal)
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
            
    def perform_lsb_attack_decimal(self) -> Tuple[decimal.Decimal, decimal.Decimal]:
        """
        Perform the LSB Oracle attack using decimal precision arithmetic.
        
        This enhanced version uses the decimal module for arbitrary precision
        arithmetic, providing better accuracy for large RSA moduli.
        
        Returns:
            Tuple[Decimal, Decimal]: Final (lower_bound, upper_bound) with decimal precision
        """
        logger.info("Starting enhanced LSB Oracle attack with decimal precision...")
        logger.info(f"Target ciphertext: {self.target_ciphertext}")
        logger.info(f"Modulus bit length: {self.modulus_n.bit_length()}")
        logger.info(f"Decimal precision: {decimal.getcontext().prec}")
        
        # Initialize search bounds with decimal precision
        upper_bound = decimal.Decimal(self.modulus_n)
        lower_bound = decimal.Decimal(0)
        
        logger.info("Initial bounds (decimal precision):")
        self.print_bounds(lower_bound, upper_bound)
        
        # Current ciphertext for queries
        current_ciphertext = self.target_ciphertext
        
        # Perform binary search using LSB oracle with decimal precision
        for iteration in range(self.modulus_n.bit_length()):
            logger.info(f"\n--- Iteration {iteration + 1} ---")
            
            # Multiply ciphertext by 2^e to double the plaintext
            # This uses the multiplicative property of RSA:
            # (c * 2^e) mod n = (m * 2) mod n
            current_ciphertext = (pow(2, self.public_exponent_e, self.modulus_n) * current_ciphertext) % self.modulus_n
            
            # Query the oracle for the LSB of the doubled plaintext
            lsb = self.query_oracle(current_ciphertext)
            logger.info(f"LSB of doubled plaintext: {lsb}")
            
            # Update bounds based on LSB using decimal precision
            if lsb == 1:
                # Plaintext is odd, so it's in the upper half
                lower_bound = (upper_bound + lower_bound) / 2
                logger.info("Plaintext is odd - updating lower bound")
            else:
                # Plaintext is even, so it's in the lower half
                upper_bound = (upper_bound + lower_bound) / 2
                logger.info("Plaintext is even - updating upper bound")
                
            # Print current bounds
            self.print_bounds(lower_bound, upper_bound)
            
            # Check if bounds have converged (with decimal precision)
            if upper_bound - lower_bound <= decimal.Decimal(1):
                logger.info("Bounds converged!")
                break
                
        return lower_bound, upper_bound
        
    def decode_result(self, bounds: Tuple[decimal.Decimal, decimal.Decimal]) -> Optional[str]:
        """
        Attempt to decode the recovered plaintext as a string.
        
        Args:
            bounds: Tuple of (lower_bound, upper_bound) as Decimal objects
            
        Returns:
            Optional[str]: Decoded string if successful, None otherwise
        """
        try:
            lower_bound, upper_bound = bounds
            
            # Convert decimal result to integer
            plaintext_int = int(upper_bound)
            
            # Convert to bytes and attempt to decode
            plaintext_bytes = self.to_bytes(plaintext_int)
            
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
        Run the complete enhanced LSB Oracle attack.
        
        This method orchestrates the entire attack process with decimal precision:
        1. Test oracle connection
        2. Perform the enhanced LSB attack
        3. Decode and display results
        """
        print("=" * 70)
        print("ENHANCED LSB ORACLE ATTACK - HIGH PRECISION RSA PLAINTEXT RECOVERY")
        print("=" * 70)
        print()
        print("This enhanced attack uses arbitrary precision decimal arithmetic")
        print("for improved accuracy with large RSA moduli.")
        print()
        print(f"Modulus bit length: {self.modulus_n.bit_length()} bits")
        print(f"Decimal precision: {decimal.getcontext().prec} digits")
        print()
        
        # Test oracle connection
        if not self.test_oracle_connection():
            print("Failed to connect to oracle server!")
            return
            
        print("Oracle connection successful. Starting enhanced attack...")
        print()
        
        # Perform the enhanced LSB attack
        try:
            bounds = self.perform_lsb_attack_decimal()
            lower_bound, upper_bound = bounds
            
            print("\n" + "=" * 70)
            print("ATTACK RESULTS")
            print("=" * 70)
            print(f"Final lower bound (decimal): {lower_bound}")
            print(f"Final upper bound (decimal): {upper_bound}")
            print(f"Plaintext (integer): {int(upper_bound)}")
            
            # Attempt to decode as string
            decoded = self.decode_result(bounds)
            if decoded:
                print(f"Plaintext (string): '{decoded}'")
            else:
                print("Could not decode plaintext as string")
                
        except Exception as e:
            logger.error(f"Attack failed: {e}")
            print(f"Attack failed: {e}")

def main():
    """
    Main function to run the enhanced LSB Oracle attack.
    
    This function demonstrates the LSB Oracle attack with decimal precision,
    showing improved accuracy for large RSA moduli.
    """
    client = LSBOracleClientDecimal()
    client.run_attack()

if __name__ == '__main__':
    main()
