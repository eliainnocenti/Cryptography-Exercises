#!/usr/bin/env python3
"""
RSA Key Material and Test Data for LSB Oracle Attack

This module contains the RSA key parameters and test data used in the LSB Oracle
attack demonstration. In a real attack scenario, the attacker would only know
the public key (n, e) and the ciphertext.

SECURITY NOTE: This is for educational purposes only. Never hardcode private
keys or expose them in real applications.

Authors: Cryptography Course
License: Educational Use Only
"""

# RSA modulus (n = p * q)
# This is the product of two large prime numbers
lsb_n = 84512936364028707109792721541348089559038960317411172574310460131821809228801

# RSA private exponent (d)
# This is the modular inverse of e modulo φ(n)
# In a real attack, this would be unknown to the attacker
lsb_d = 33338617022738821809198944565794469679031084241028925158776770023255471009649

# RSA public exponent (e)
# Commonly 65537 (0x10001) for efficiency and security
lsb_e = 65537

# Target ciphertext for the LSB Oracle attack
# This is the encrypted message that the attacker wants to decrypt
lsb_ciphertext = 40905797042890600077330500098053021483209678644028914795144404253281221960366

# Original plaintext (for verification purposes)
# In a real attack, this would be unknown to the attacker
lsb_plaintext = 803417515832054223369196934329960786582357242441556610682060160426930292

# Additional information for educational purposes
def print_key_info():
    """Print information about the RSA key parameters."""
    print("RSA Key Information:")
    print(f"Modulus bit length: {lsb_n.bit_length()} bits")
    print(f"Public exponent (e): {lsb_e}")
    print(f"Modulus (n): {lsb_n}")
    print(f"Private exponent (d): {lsb_d}")
    print(f"Target ciphertext: {lsb_ciphertext}")
    print(f"Original plaintext: {lsb_plaintext}")
    
    # Verify the RSA parameters
    print("\nVerification:")
    print(f"Encryption check: {pow(lsb_plaintext, lsb_e, lsb_n) == lsb_ciphertext}")
    print(f"Decryption check: {pow(lsb_ciphertext, lsb_d, lsb_n) == lsb_plaintext}")

if __name__ == '__main__':
    print_key_info()
