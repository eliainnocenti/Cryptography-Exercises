#!/usr/bin/env python3
"""
Test data for CBC Padding Oracle Attack demonstration.

This file contains the IV and ciphertext data used for demonstrating
the padding oracle attack. In a real attack scenario, this data would
be obtained through interception of network traffic or other means.

Security Note:
The commented lines show different ciphertext examples that can be used
for testing various scenarios and attack techniques.
"""

# Initialization Vector (IV) for AES-CBC
# This 16-byte IV is used to initialize the CBC mode encryption
cbc_oracle_iv = b'\xd9H\xaf\xc9\xa5\xc9"3\x93\xaa\xbd\x87\xa5\x15\x04\xdd'

# Target ciphertext for the padding oracle attack
# This represents the encrypted message that the attacker wants to decrypt
# The attacker has access to this ciphertext but not the encryption key
cbc_oracle_ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbc\xa3{\xa1\x05_\xd5\xc0\xa4\xa0\xc5\xdaI\x11\xf3\x93\xb4'

# Alternative ciphertext examples for testing (commented out)
# These can be used to test different attack scenarios:

# Example 1: Different padding scenarios
# cbc_oracle_ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbc\x82\xb0d2\x0bm\xc7\xdeX)\xb2\x7f\xb2\xe7I\x14'

# Example 2: Longer message with more blocks
# cbc_oracle_ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbcS\xac\xd9\xb9\xbb\xfaI\x87\xa3E\x8aT8//\xf4\xb0\xa9u\x8c\x0eQ\x1c\x83v\xed\x04`\n\xf7\xcc\x03'

# Example 3: Different block structure
# cbc_oracle_ciphertext = b'r\x8b\x14\xd6\xae{J\xa0\xe3\x9e\n\x96>\xf9=c\x0f\x16\x9at\x80\ny\xcfD\x08\xe7\xbe\xc1\x8d\x06U\x17J\xb4.\xe1\x9b48R\x8d\xd7\x04\xad\x0b\x7f\xbc\xa3{\xa1\x05_\xd5\xc0\xa4\xa0\xc5\xdaI\x11\xf3\x93\xb4'

# Attack Information:
# - Ciphertext length: 64 bytes (4 blocks of 16 bytes each)
# - Target: Decrypt the message without knowing the encryption key
# - Method: Exploit padding validation information leakage
# - Expected plaintext: '03LPYOV{How_many_nice_things_can_you_find_1_bit_at_the_time?}'

