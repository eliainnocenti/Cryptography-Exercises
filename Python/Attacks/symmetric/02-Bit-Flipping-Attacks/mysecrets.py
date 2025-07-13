#!/usr/bin/env python3
"""
Cryptographic Secrets for Bit-Flipping Attack Exercises

This file contains the cryptographic keys and secrets used in the bit-flipping
attack demonstrations. These values are used by both the vulnerable server
and the attack client.

⚠️ WARNING: These are demo keys for educational purposes only!
Never use hardcoded keys in production systems.
"""

from Crypto.Random import get_random_bytes

# Secret message used for testing encryption in ECB mode
ecb_oracle_secret = "Here's my secret"

# Longer secret message used for testing encryption in ECB mode
ecb_oracle_long_secret = "Here's my very long secret"

# Key used for AES encryption (shared between server and client)
ecb_oracle_key = b'\x1e\x86\x114\x0b\x8d6k`\xb1\xdc\xb5\xa9\xc7,\xe8A\xe2\x1c\x0bk\x93Lc\xc0\xa9\xce\xae\xcc.z\xd2'

# Key used for bit-flipping attack demonstrations
bf_key = b'\x1e\x86\x114\x0b\x8d6k`\xb1\xdc\xb5\xa9\xc7,\xe8A\xe2\x1c\x0bk\x93Lc\xc0\xa9\xce\xae\xcc.z\xd2'

# Initialization Vector (IV) for CBC mode in bit-flipping attacks
# Note: Using a fixed IV is insecure in practice, but acceptable for educational demos
bf_iv = b'\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12\x34\x56\x78\x9a\xbc\xde\xf0'
