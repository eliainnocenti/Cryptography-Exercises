#!/usr/bin/env python3
"""
MD5 Length Extension Attack Implementation

This module provides a pure Python implementation of the MD5 hash algorithm
with support for length extension attacks. It demonstrates how the MD5 hash
function can be vulnerable to length extension attacks due to its Merkle-Damgård
construction.

ATTACK OVERVIEW:
Similar to SHA-1, MD5 is vulnerable to length extension attacks. An attacker
can append data to a message and compute the hash of the extended message
without knowing the original message or secret key.

VULNERABILITY:
MD5 uses the Merkle-Damgård construction where:
- The internal state is directly used as the hash output
- New data can be appended by resuming from a known state
- The padding scheme is predictable

SECURITY IMPLICATIONS:
- Breaks authentication schemes using H(secret||message)
- Enables message forgery attacks
- Demonstrates fundamental weakness in the construction

DEFENSIVE MEASURES:
- Use HMAC for authentication
- Avoid simple concatenation schemes
- Use modern hash functions (SHA-3, BLAKE2)

ORIGINAL COPYRIGHT:
Derived from RSA Data Security, Inc. MD5 Message-Digest Algorithm
Copyright (C) 1991-2, RSA Data Security, Inc.

Modified for educational purposes to demonstrate length extension attacks.
"""

import struct
import logging
from typing import Union, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

__doc__ = """pymd5 module - The MD5 hash function in pure Python with length extension support.

md5(string='', state=None, count=0) - Returns a new md5 object and processes string.
        Optional advanced parameters allow you to resume an earlier computation by
        setting the internal state and the counter of message bits processed.

Most of the interface matches Python's standard hashlib, with extensions for
length extension attacks.

md5 objects have these methods and attributes:

 - update(arg): Update the md5 object with the string arg. Repeated calls
                are equivalent to a single call with the concatenation of all
                the arguments.
 - digest():    Return the digest of the strings passed to the update() method
                so far. This may contain non-ASCII characters, including
                NUL bytes.
 - hexdigest(): Like digest() except the digest is returned as a string of
                double length, containing only hexadecimal digits.

 - digest_size: The size of the resulting hash in bytes (16).
 - block_size:  The internal block size of the hash algorithm in bytes (64).

For length extension attacks, additional methods are provided:

 - md5_compress(state, block): The MD5 compression function; returns a
                               new 16-byte state based on the 16-byte
                               previous state and a 512-byte message block.

 - padding(msg_bits):          Generate the padding that should be appended
                               to the end of a message of the given size to
                               reach a multiple of the block size.

Example usage:

    >>> import pymd5
    >>> m = pymd5.md5()
    >>> m.update("Nobody inspects")
    >>> m.update(" the spammish repetition")
    >>> m.digest()

Length extension attack example:

    >>> # Assume we know the hash of secret||message
    >>> known_hash = b'\\x12\\x34\\x56\\x78...'  # 16 bytes
    >>> # Create new MD5 instance with known state
    >>> m = pymd5.md5(state=known_hash, count=original_length * 8)
    >>> m.update(additional_data)
    >>> extended_hash = m.digest()
"""

# MD5 Algorithm Constants

# Shift amounts for each round
S11, S12, S13, S14 = 7, 12, 17, 22
S21, S22, S23, S24 = 5, 9, 14, 20
S31, S32, S33, S34 = 4, 11, 16, 23
S41, S42, S43, S44 = 6, 10, 15, 21

# MD5 padding: starts with 0x80, followed by zeros
PADDING = b"\x80" + 63 * b"\0"

# MD5 auxiliary functions
def F(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function F: (x & y) | (~x & z)"""
    return (x & y) | (~x & z)

def G(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function G: (x & z) | (y & ~z)"""
    return (x & z) | (y & ~z)

def H(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function H: x ^ y ^ z"""
    return x ^ y ^ z

def I(x: int, y: int, z: int) -> int:
    """MD5 auxiliary function I: y ^ (x | ~z)"""
    return y ^ (x | ~z)

def ROTATE_LEFT(x: int, n: int) -> int:
    """
    Rotate a 32-bit integer left by n bits.
    
    Args:
        x: 32-bit integer to rotate
        n: Number of bits to rotate left
        
    Returns:
        int: Rotated value
    """
    x = x & 0xffffffff  # Ensure 32-bit
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

# MD5 round functions
def FF(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:
    """MD5 round function for round 1"""
    a = (a + F(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT(a, s)
    a = (a + b) & 0xffffffff
    return a

def GG(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:
    """MD5 round function for round 2"""
    a = (a + G(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT(a, s)
    a = (a + b) & 0xffffffff
    return a

def HH(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:
    """MD5 round function for round 3"""
    a = (a + H(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT(a, s)
    a = (a + b) & 0xffffffff
    return a

def II(a: int, b: int, c: int, d: int, x: int, s: int, ac: int) -> int:
    """MD5 round function for round 4"""
    a = (a + I(b, c, d) + x + ac) & 0xffffffff
    a = ROTATE_LEFT(a, s)
    a = (a + b) & 0xffffffff
    return a

class md5:
    """
    MD5 hash algorithm implementation with length extension attack support.
    
    This implementation allows for length extension attacks by enabling
    initialization with a known internal state and bit count.
    """
    
    digest_size = 16  # MD5 produces 16-byte (128-bit) hashes
    block_size = 64   # MD5 processes 64-byte (512-bit) blocks

    def __init__(self, string: Union[str, bytes] = '', 
                 state: Optional[bytes] = None, 
                 count: int = 0):
        """
        Initialize MD5 hash object.
        
        Args:
            string: Initial data to hash
            state: Optional 16-byte state for length extension attacks
            count: Bit count for length extension attacks
        """
        self.count = 0
        self.buffer = b""

        if state is None:
            # Standard MD5 initialization values
            self.state = (
                0x67452301,  # A
                0xefcdab89,  # B
                0x98badcfe,  # C
                0x10325476,  # D
            )
            logger.debug("MD5 initialized with standard constants")
        else:
            # Initialize with provided state (for length extension attacks)
            if len(state) != self.digest_size:
                raise ValueError(f"State must be {self.digest_size} bytes")
            self.state = _decode(state, self.digest_size)
            logger.info(f"MD5 initialized with provided state: {state.hex()}")

        if count is not None:
            self.count = count
            logger.debug(f"MD5 bit count set to: {count}")

        if string:
            self.update(string)

    def update(self, input_data: Union[str, bytes]) -> None:
        """
        Update the MD5 hash with new data.
        
        Args:
            input_data: Data to add to the hash
        """
        if not isinstance(input_data, bytes):
            input_data = input_data.encode('utf-8')
            
        inputLen = len(input_data)
        logger.debug(f"Updating MD5 with {inputLen} bytes")
        
        # Calculate current position in buffer
        index = int(self.count >> 3) & 0x3F
        
        # Update bit count
        self.count = self.count + (inputLen << 3)
        
        # Calculate how many bytes we need to complete current block
        partLen = self.block_size - index

        # Process complete blocks
        if inputLen >= partLen:
            # Complete current block
            self.buffer = self.buffer[:index] + input_data[:partLen]
            self.state = md5_compress(self.state, self.buffer)
            
            # Process remaining complete blocks
            i = partLen
            while i + 63 < inputLen:
                self.state = md5_compress(self.state, input_data[i:i + self.block_size])
                i = i + self.block_size
            index = 0
        else:
            i = 0

        # Buffer remaining input
        self.buffer = self.buffer[:index] + input_data[i:inputLen]

    def digest(self) -> bytes:
        """
        Return the MD5 hash as bytes.
        
        Returns:
            bytes: 16-byte MD5 hash
        """
        # Save current state
        _buffer, _count, _state = self.buffer, self.count, self.state
        
        # Add padding and process final block
        self.update(padding(self.count))
        result = self.state
        
        # Restore state (allows multiple digest calls)
        self.buffer, self.count, self.state = _buffer, _count, _state
        
        return _encode(result, self.digest_size)

    def hexdigest(self) -> str:
        """
        Return the MD5 hash as a hexadecimal string.
        
        Returns:
            str: 32-character hex string
        """
        return self.digest().hex()

    def copy(self) -> 'md5':
        """
        Return a copy of the MD5 object.
        
        Returns:
            md5: Copy of this MD5 object
        """
        new_md5 = md5()
        new_md5.buffer = self.buffer
        new_md5.count = self.count
        new_md5.state = self.state
        return new_md5

def padding(msg_bits: int) -> bytes:
    """
    Generate MD5 padding for a message of given bit length.
    
    The MD5 padding scheme:
    1. Append a single '1' bit (0x80 byte)
    2. Append zero or more '0' bits until message length ≡ 448 (mod 512)
    3. Append the original message length as a 64-bit little-endian integer
    
    Args:
        msg_bits: Length of the message in bits
        
    Returns:
        bytes: Padding to append to the message
    """
    # Calculate current position in 64-byte block
    index = int((msg_bits >> 3) & 0x3f)
    
    # Calculate padding length
    if index < 56:
        padLen = 56 - index
    else:
        padLen = 120 - index

    # Create padding: 0x80 + zeros + length
    pad = PADDING[:padLen] + _encode((msg_bits & 0xffffffff, msg_bits >> 32), 8)
    
    logger.debug(f"Generated {len(pad)} bytes of padding for {msg_bits} bits")
    return pad

def md5_compress(state: Tuple[int, int, int, int], block: bytes) -> Tuple[int, int, int, int]:
    """
    MD5 compression function - processes one 512-bit block.
    
    This is the core MD5 function that can be used for length extension attacks
    by resuming computation from a known state.
    
    Args:
        state: Current MD5 state as 4 32-bit integers (A, B, C, D)
        block: 64-byte (512-bit) message block
        
    Returns:
        Tuple[int, int, int, int]: New MD5 state
    """
    if len(block) != 64:
        raise ValueError("Block must be exactly 64 bytes")
        
    # Initialize working variables
    a, b, c, d = state
    
    # Decode block into 16 32-bit words (little-endian)
    x = _decode(block, 64)

    # Round 1
    a = FF(a, b, c, d, x[0], S11, 0xd76aa478)
    d = FF(d, a, b, c, x[1], S12, 0xe8c7b756)
    c = FF(c, d, a, b, x[2], S13, 0x242070db)
    b = FF(b, c, d, a, x[3], S14, 0xc1bdceee)
    a = FF(a, b, c, d, x[4], S11, 0xf57c0faf)
    d = FF(d, a, b, c, x[5], S12, 0x4787c62a)
    c = FF(c, d, a, b, x[6], S13, 0xa8304613)
    b = FF(b, c, d, a, x[7], S14, 0xfd469501)
    a = FF(a, b, c, d, x[8], S11, 0x698098d8)
    d = FF(d, a, b, c, x[9], S12, 0x8b44f7af)
    c = FF(c, d, a, b, x[10], S13, 0xffff5bb1)
    b = FF(b, c, d, a, x[11], S14, 0x895cd7be)
    a = FF(a, b, c, d, x[12], S11, 0x6b901122)
    d = FF(d, a, b, c, x[13], S12, 0xfd987193)
    c = FF(c, d, a, b, x[14], S13, 0xa679438e)
    b = FF(b, c, d, a, x[15], S14, 0x49b40821)

    # Round 2
    a = GG(a, b, c, d, x[1], S21, 0xf61e2562)
    d = GG(d, a, b, c, x[6], S22, 0xc040b340)
    c = GG(c, d, a, b, x[11], S23, 0x265e5a51)
    b = GG(b, c, d, a, x[0], S24, 0xe9b6c7aa)
    a = GG(a, b, c, d, x[5], S21, 0xd62f105d)
    d = GG(d, a, b, c, x[10], S22, 0x2441453)
    c = GG(c, d, a, b, x[15], S23, 0xd8a1e681)
    b = GG(b, c, d, a, x[4], S24, 0xe7d3fbc8)
    a = GG(a, b, c, d, x[9], S21, 0x21e1cde6)
    d = GG(d, a, b, c, x[14], S22, 0xc33707d6)
    c = GG(c, d, a, b, x[3], S23, 0xf4d50d87)
    b = GG(b, c, d, a, x[8], S24, 0x455a14ed)
    a = GG(a, b, c, d, x[13], S21, 0xa9e3e905)
    d = GG(d, a, b, c, x[2], S22, 0xfcefa3f8)
    c = GG(c, d, a, b, x[7], S23, 0x676f02d9)
    b = GG(b, c, d, a, x[12], S24, 0x8d2a4c8a)

    # Round 3
    a = HH(a, b, c, d, x[5], S31, 0xfffa3942)
    d = HH(d, a, b, c, x[8], S32, 0x8771f681)
    c = HH(c, d, a, b, x[11], S33, 0x6d9d6122)
    b = HH(b, c, d, a, x[14], S34, 0xfde5380c)
    a = HH(a, b, c, d, x[1], S31, 0xa4beea44)
    d = HH(d, a, b, c, x[4], S32, 0x4bdecfa9)
    c = HH(c, d, a, b, x[7], S33, 0xf6bb4b60)
    b = HH(b, c, d, a, x[10], S34, 0xbebfbc70)
    a = HH(a, b, c, d, x[13], S31, 0x289b7ec6)
    d = HH(d, a, b, c, x[0], S32, 0xeaa127fa)
    c = HH(c, d, a, b, x[3], S33, 0xd4ef3085)
    b = HH(b, c, d, a, x[6], S34, 0x4881d05)
    a = HH(a, b, c, d, x[9], S31, 0xd9d4d039)
    d = HH(d, a, b, c, x[12], S32, 0xe6db99e5)
    c = HH(c, d, a, b, x[15], S33, 0x1fa27cf8)
    b = HH(b, c, d, a, x[2], S34, 0xc4ac5665)

    # Round 4
    a = II(a, b, c, d, x[0], S41, 0xf4292244)
    d = II(d, a, b, c, x[7], S42, 0x432aff97)
    c = II(c, d, a, b, x[14], S43, 0xab9423a7)
    b = II(b, c, d, a, x[5], S44, 0xfc93a039)
    a = II(a, b, c, d, x[12], S41, 0x655b59c3)
    d = II(d, a, b, c, x[3], S42, 0x8f0ccc92)
    c = II(c, d, a, b, x[10], S43, 0xffeff47d)
    b = II(b, c, d, a, x[1], S44, 0x85845dd1)
    a = II(a, b, c, d, x[8], S41, 0x6fa87e4f)
    d = II(d, a, b, c, x[15], S42, 0xfe2ce6e0)
    c = II(c, d, a, b, x[6], S43, 0xa3014314)
    b = II(b, c, d, a, x[13], S44, 0x4e0811a1)
    a = II(a, b, c, d, x[4], S41, 0xf7537e82)
    d = II(d, a, b, c, x[11], S42, 0xbd3af235)
    c = II(c, d, a, b, x[2], S43, 0x2ad7d2bb)
    b = II(b, c, d, a, x[9], S44, 0xeb86d391)

    # Add the compressed chunk to the current hash value
    return (
        (state[0] + a) & 0xffffffff,
        (state[1] + b) & 0xffffffff,
        (state[2] + c) & 0xffffffff,
        (state[3] + d) & 0xffffffff,
    )

def _encode(input_tuple: Tuple[int, ...], length: int) -> bytes:
    """
    Encode a tuple of integers as little-endian bytes.
    
    Args:
        input_tuple: Tuple of integers to encode
        length: Total byte length of output
        
    Returns:
        bytes: Little-endian byte representation
    """
    k = length // 4
    return struct.pack("<%iI" % k, *input_tuple[:k])

def _decode(input_bytes: bytes, length: int) -> list:
    """
    Decode little-endian bytes into a list of integers.
    
    Args:
        input_bytes: Bytes to decode
        length: Number of bytes to decode
        
    Returns:
        list: List of 32-bit integers
    """
    k = length // 4
    return list(struct.unpack("<%iI" % k, input_bytes[:length]))

def demonstrate_md5_length_extension():
    """
    Demonstrate the MD5 length extension attack.
    
    This function shows how an attacker can extend a message and compute
    the MD5 hash of the extended message without knowing the original secret.
    """
    print("=" * 70)
    print("MD5 LENGTH EXTENSION ATTACK DEMONSTRATION")
    print("=" * 70)
    print()
    
    # Setup: Secret key and original message
    secret = b'secret_key_12345'
    original_message = b'user=admin&action=view'
    malicious_extension = b'&action=delete&target=all'
    
    print(f"Secret key: {secret}")
    print(f"Original message: {original_message}")
    print(f"Malicious extension: {malicious_extension}")
    print()
    
    # Step 1: Compute the original hash H(secret||message)
    print("Step 1: Computing original hash")
    original_combined = secret + original_message
    original_hash = md5(original_combined).digest()
    print(f"Original hash: {original_hash.hex()}")
    print(f"Original length: {len(original_combined)} bytes")
    print()
    
    # Step 2: Determine the padding
    print("Step 2: Determining padding")
    original_bit_length = len(original_combined) * 8
    required_padding = padding(original_bit_length)
    print(f"Required padding: {len(required_padding)} bytes")
    print(f"Padding (hex): {required_padding.hex()}")
    print()
    
    # Step 3: Perform the length extension attack
    print("Step 3: Performing length extension attack")
    print("Attacker knows:")
    print(f"  - Original hash: {original_hash.hex()}")
    print(f"  - Original combined length: {len(original_combined)} bytes")
    print(f"  - Extension data: {malicious_extension}")
    print()
    
    # Calculate the bit count after padding
    padded_length = len(original_combined) + len(required_padding)
    bit_count_after_padding = padded_length * 8
    
    # Create MD5 object with the known hash as initial state
    attack_md5 = md5(state=original_hash, count=bit_count_after_padding)
    attack_md5.update(malicious_extension)
    attack_result = attack_md5.digest()
    
    print(f"Attack result: {attack_result.hex()}")
    print()
    
    # Step 4: Verify the attack
    print("Step 4: Verifying the attack")
    full_message = original_combined + required_padding + malicious_extension
    legitimate_hash = md5(full_message).digest()
    
    print(f"Full message: {full_message}")
    print(f"Legitimate hash: {legitimate_hash.hex()}")
    print(f"Attack hash:    {attack_result.hex()}")
    print()
    
    if attack_result == legitimate_hash:
        print("✓ ATTACK SUCCESSFUL!")
        print("The attacker successfully forged the hash without knowing the secret!")
    else:
        print("✗ Attack failed")
    
    print()
    print("=" * 70)
    print("ATTACK IMPLICATIONS")
    print("=" * 70)
    print("The attacker can now present:")
    print(f"Message: {original_message + required_padding + malicious_extension}")
    print(f"Hash: {attack_result.hex()}")
    print("And claim it was authenticated with the secret key!")

def test(input_string: str = "") -> None:
    """
    Test function to compare our MD5 implementation with the standard library.
    
    Args:
        input_string: String to hash for testing
    """
    import hashlib
    
    print(f"Testing with input: '{input_string}'")
    print(f"Our MD5:      {md5(input_string).hexdigest()}")
    print(f"Standard MD5: {hashlib.md5(input_string.encode('utf-8')).hexdigest()}")

def main():
    """
    Main function to demonstrate MD5 length extension attack.
    """
    print("Testing MD5 implementation...")
    test("The quick brown fox jumps over the lazy dog")
    print()
    
    demonstrate_md5_length_extension()

if __name__ == '__main__':
    main()
