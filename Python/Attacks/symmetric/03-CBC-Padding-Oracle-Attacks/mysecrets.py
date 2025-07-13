#!/usr/bin/env python3
"""
Secret key for CBC Padding Oracle Attack demonstration.

This file contains the secret encryption key used by the vulnerable server.
In a real attack scenario, this key would be unknown to the attacker.

Security Note:
- This key is for educational purposes only
- The attacker's goal is to decrypt messages WITHOUT knowing this key
- The padding oracle attack exploits information leakage, not key recovery
- In practice, never hardcode encryption keys in source code
"""

# AES-256 encryption key (32 bytes)
# This key is used by the vulnerable server for CBC encryption/decryption
# The attacker does NOT have access to this key in a real attack
cbc_oracle_key = b'0123456789abcdef0123456789abcdef'

# Key Information:
# - Length: 32 bytes (256 bits)
# - Used for: AES-CBC encryption/decryption
# - Security: This is a weak key for demonstration purposes
# - Attack goal: Decrypt ciphertext WITHOUT knowing this key