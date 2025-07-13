#!/usr/bin/env python3
"""
SHA-1 Length Extension Attack Implementation

This module demonstrates the SHA-1 length extension attack, a cryptographic attack
that exploits the Merkle-Damgård construction used in SHA-1 and other hash functions.

ATTACK OVERVIEW:
The length extension attack allows an attacker to append data to a message and
compute the hash of the extended message, even without knowing the original message
or secret key, given only the hash of the original message and its length.

MATHEMATICAL FOUNDATION:
SHA-1 uses the Merkle-Damgård construction:
- The message is padded and processed in 512-bit blocks
- Each block updates an internal state using a compression function
- The final state becomes the hash output

ATTACK METHODOLOGY:
1. Start with a known hash H(secret||message)
2. Determine the internal state from the hash
3. Append padding as if continuing the original message
4. Add new data and compute the hash of the extended message
5. Result: H(secret||message||padding||new_data)

SECURITY IMPLICATIONS:
- Breaks authentication schemes using H(secret||message)
- Enables message forgery in vulnerable authentication systems
- Demonstrates why HMAC is necessary for secure authentication

DEFENSIVE MEASURES:
- Use HMAC instead of simple hash concatenation
- Implement length-prefixed schemes: H(length||message)
- Use modern hash functions with built-in authentication (SHA-3, BLAKE2)
"""

import sys
import logging
from hashlib import sha1
from typing import Optional, List, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pre-computed hash for demonstration (represents H(secret||message))
sniffed_dgst = "13cf30c5374f2dfb45e71d9e1606f8b8a3f7b342"

class SHA1LengthExtension:
    """
    SHA-1 Length Extension Attack Implementation
    
    This class implements a SHA-1 hasher that can be initialized with a known
    hash value, enabling length extension attacks.
    """
    
    def __init__(self, initial_hash: Optional[str] = None):
        """
        Initialize the SHA-1 hasher.
        
        Args:
            initial_hash: Optional hex string of initial hash state
                         If provided, allows for length extension attacks
        """
        if initial_hash is None:
            # Standard SHA-1 initialization constants
            self.__H = [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0
            ]
            logger.info("SHA-1 initialized with standard constants")
        else:
            # Initialize with provided hash (for length extension attack)
            self.__H = [None] * 5
            for i in range(5):
                # Parse hex string into 32-bit words
                hex_word = "0x" + initial_hash[i * 8:(i + 1) * 8]
                self.__H[i] = int(hex_word, 16)
            logger.info(f"SHA-1 initialized with hash: {initial_hash}")
            logger.info(f"Internal state: {[hex(h) for h in self.__H]}")

    def __str__(self) -> str:
        """
        Return the current hash as a hex string.
        
        Returns:
            str: Hex representation of the current hash
        """
        return ''.join((hex(h)[2:]).rjust(8, '0') for h in self.__H)

    @staticmethod
    def __ROTL(n: int, x: int, w: int = 32) -> int:
        """
        Rotate left operation for SHA-1.
        
        Args:
            n: Number of bits to rotate
            x: Value to rotate
            w: Word size (default 32 bits)
            
        Returns:
            int: Rotated value
        """
        return ((x << n) | (x >> (w - n))) & ((1 << w) - 1)

    @staticmethod
    def __padding(stream: Union[str, bytes], additional_length: int = 0) -> Union[str, bytes]:
        """
        Apply SHA-1 padding to a message.
        
        The padding scheme adds:
        1. A single '1' bit (0x80 byte)
        2. Zero or more '0' bits to make the message length ≡ 448 (mod 512)
        3. The original message length as a 64-bit big-endian integer
        
        Args:
            stream: Message to pad
            additional_length: Additional length to add (for length extension)
            
        Returns:
            Union[str, bytes]: Padded message
        """
        # Calculate the total length including any additional length
        l = len(stream) + additional_length  # Length in bytes
        
        # Convert length to bits and create 64-bit representation
        length_bits = l * 8
        hl = [int((hex(length_bits)[2:]).rjust(16, '0')[i:i + 2], 16)
              for i in range(0, 16, 2)]

        # Calculate padding length
        # We need the message length to be ≡ 448 (mod 512) bits
        # or ≡ 56 (mod 64) bytes
        l0 = (56 - (l % 64)) % 64
        if l0 == 0:
            l0 = 64

        # Apply padding
        if isinstance(stream, str):
            # String padding
            stream += chr(0b10000000)  # Add '1' bit
            stream += chr(0) * (l0 - 1)  # Add zero padding
            for byte_val in hl:
                stream += chr(byte_val)  # Add length
        elif isinstance(stream, bytes):
            # Bytes padding
            stream += bytes([0b10000000])  # Add '1' bit
            stream += bytes(l0 - 1)  # Add zero padding
            stream += bytes(hl)  # Add length

        return stream

    @staticmethod
    def __prepare(stream: Union[str, bytes]) -> List[List[int]]:
        """
        Prepare the message for SHA-1 processing by splitting into 512-bit blocks.
        
        Args:
            stream: Padded message
            
        Returns:
            List[List[int]]: List of 512-bit blocks, each as 16 32-bit words
        """
        M = []
        n_blocks = len(stream) // 64  # 64 bytes per block

        if isinstance(stream, str):
            stream = stream.encode('utf-8')
        stream = bytearray(stream)

        for i in range(n_blocks):
            m = []
            for j in range(16):  # 16 32-bit words per block
                # Combine 4 bytes into a 32-bit word (big-endian)
                word = 0
                for k in range(4):
                    word = (word << 8) | stream[i * 64 + j * 4 + k]
                m.append(word)
            M.append(m)

        return M

    @staticmethod
    def __debug_print(t: int, a: int, b: int, c: int, d: int, e: int) -> None:
        """
        Debug function to print SHA-1 round values.
        
        Args:
            t: Round number
            a, b, c, d, e: SHA-1 state values
        """
        print(f't = {t}: \t',
              (hex(a)[2:]).rjust(8, '0'),
              (hex(b)[2:]).rjust(8, '0'),
              (hex(c)[2:]).rjust(8, '0'),
              (hex(d)[2:]).rjust(8, '0'),
              (hex(e)[2:]).rjust(8, '0'))

    def __process_block(self, block: List[int]) -> None:
        """
        Process a single 512-bit block through the SHA-1 compression function.
        
        Args:
            block: 512-bit block as 16 32-bit words
        """
        MASK = 2**32 - 1  # 32-bit mask

        # Extend the 16 words to 80 words
        W = block[:]
        for t in range(16, 80):
            W.append(self.__ROTL(1, (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])) & MASK)

        # Initialize working variables
        a, b, c, d, e = self.__H[:]

        # Main SHA-1 loop (80 rounds)
        for t in range(80):
            # Select function and constant based on round
            if t <= 19:
                K = 0x5a827999
                f = (b & c) ^ (~b & d)
            elif t <= 39:
                K = 0x6ed9eba1
                f = b ^ c ^ d
            elif t <= 59:
                K = 0x8f1bbcdc
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                K = 0xca62c1d6
                f = b ^ c ^ d

            # SHA-1 round function
            T = (self.__ROTL(5, a) + f + e + K + W[t]) & MASK
            e = d
            d = c
            c = self.__ROTL(30, b) & MASK
            b = a
            a = T

        # Update hash state
        self.__H[0] = (a + self.__H[0]) & MASK
        self.__H[1] = (b + self.__H[1]) & MASK
        self.__H[2] = (c + self.__H[2]) & MASK
        self.__H[3] = (d + self.__H[3]) & MASK
        self.__H[4] = (e + self.__H[4]) & MASK

    def update(self, stream: Union[str, bytes], additional_length: int = 0) -> None:
        """
        Update the hash with new data.
        
        Args:
            stream: Data to hash
            additional_length: Additional length for length extension attacks
        """
        logger.info(f"Updating hash with data: {stream}")
        
        # Apply padding
        padded_stream = self.__padding(stream, additional_length)
        logger.info(f"Padded stream length: {len(padded_stream)} bytes")
        
        # Prepare blocks
        blocks = self.__prepare(padded_stream)
        logger.info(f"Processing {len(blocks)} blocks")

        # Process each block
        for i, block in enumerate(blocks):
            logger.debug(f"Processing block {i + 1}/{len(blocks)}")
            self.__process_block(block)

    def digest(self) -> bytes:
        """
        Return the digest as bytes.
        
        Returns:
            bytes: SHA-1 digest
        """
        # Convert internal state to bytes
        result = b''
        for h in self.__H:
            result += h.to_bytes(4, 'big')
        return result

    def hexdigest(self) -> str:
        """
        Return the digest as a hexadecimal string.
        
        Returns:
            str: SHA-1 digest in hex format
        """
        return ''.join((hex(h)[2:]).rjust(8, '0') for h in self.__H)

def create_padding(message: Union[str, bytes], additional_length: int = 0) -> Union[str, bytes]:
    """
    Create SHA-1 padding for a message.
    
    This function is used to create the padding that would be applied to a message
    during SHA-1 hashing, which is essential for length extension attacks.
    
    Args:
        message: Original message
        additional_length: Additional length to account for (e.g., secret key length)
        
    Returns:
        Union[str, bytes]: Padded message
    """
    return SHA1LengthExtension._SHA1LengthExtension__padding(message, additional_length)

def demonstrate_length_extension_attack():
    """
    Demonstrate the SHA-1 length extension attack.
    
    This function shows how an attacker can extend a message and compute
    the hash of the extended message without knowing the original secret.
    """
    print("=" * 70)
    print("SHA-1 LENGTH EXTENSION ATTACK DEMONSTRATION")
    print("=" * 70)
    print()
    
    # Setup: Secret key and original message
    secret = b'this is a secret!!'
    original_message = b'This is the message'
    message_to_append = b' ...and this is the message to append'
    
    print(f"Secret key: {secret}")
    print(f"Original message: {original_message}")
    print(f"Message to append: {message_to_append}")
    print(f"Combined length: {len(secret + original_message)} bytes")
    print()
    
    # Step 1: Compute legitimate hash H(secret||message)
    print("Step 1: Computing legitimate hash H(secret||message)")
    legitimate_hasher = sha1()
    legitimate_hasher.update(secret + original_message)
    legitimate_hash = legitimate_hasher.hexdigest()
    print(f"Legitimate hash: {legitimate_hash}")
    print()
    
    # Step 2: Create the padding that would be applied
    print("Step 2: Determining padding for original message")
    original_with_padding = create_padding(secret + original_message)
    print(f"Padded message length: {len(original_with_padding)} bytes")
    print()
    
    # Step 3: Compute what the full legitimate hash would be
    print("Step 3: Computing full legitimate hash (for verification)")
    full_legitimate_hasher = sha1()
    full_legitimate_hasher.update(original_with_padding + message_to_append)
    full_legitimate_hash = full_legitimate_hasher.hexdigest()
    print(f"Full legitimate hash: {full_legitimate_hash}")
    print()
    
    # Step 4: Perform the length extension attack
    print("Step 4: Performing length extension attack")
    print("Attacker knows:")
    print(f"  - Original hash: {legitimate_hash}")
    print(f"  - Original message length: {len(secret + original_message)} bytes")
    print(f"  - Message to append: {message_to_append}")
    print()
    
    # Initialize SHA-1 with the known hash
    attack_hasher = SHA1LengthExtension(legitimate_hash)
    
    # Append the new message (no additional length since we're continuing)
    attack_hasher.update(message_to_append)
    attack_hash = attack_hasher.hexdigest()
    
    print(f"Attack result hash: {attack_hash}")
    print()
    
    # Step 5: Verify the attack
    print("Step 5: Verifying the attack")
    if attack_hash == full_legitimate_hash:
        print("✓ ATTACK SUCCESSFUL!")
        print("The attacker successfully computed H(secret||message||padding||new_data)")
        print("without knowing the secret key!")
    else:
        print("✗ Attack failed")
        print(f"Expected: {full_legitimate_hash}")
        print(f"Got:      {attack_hash}")

def main():
    """
    Main function to demonstrate the SHA-1 length extension attack.
    """
    demonstrate_length_extension_attack()

if __name__ == '__main__':
    main()
