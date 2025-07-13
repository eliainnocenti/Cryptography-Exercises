#!/usr/bin/env python3
"""
Keystream Reuse Attack Implementation

This script demonstrates a practical attack against stream ciphers when the same
keystream is reused to encrypt multiple messages. This is one of the most
fundamental attacks in cryptography, showing why nonce reuse is catastrophic.

Attack Overview:
When the same keystream K is used to encrypt multiple plaintexts:
- C1 = P1 ⊕ K
- C2 = P2 ⊕ K
- C1 ⊕ C2 = P1 ⊕ P2 (keystream cancels out)

By analyzing character frequencies and patterns in the XORed ciphertexts,
we can recover the original plaintexts without knowing the key.

Educational Purpose:
This demonstrates why proper nonce/IV management is critical in stream ciphers
and authenticated encryption modes like CTR and GCM.
"""

from base64 import b64decode
import numpy as np
from string import ascii_letters, printable
from Crypto.Util.strxor import strxor

# English character frequency analysis data
# These frequencies are used to score potential decryptions
CHARACTER_FREQ = {
    'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 
    'f': 0.0197881, 'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 
    'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513, 'o': 0.0596302, 
    'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 
    'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 
    'z': 0.0007836, ' ': 0.1918182
}

# Test data: Base64-encoded ciphertexts encrypted with the same keystream
# In a real attack, these would be intercepted network traffic or stolen data
# This dataset contains multiple messages encrypted with the same key/nonce pair
encoded_ciphertexts = [
    b'wMf5jRaW+h+ZIzmbCVPA2jRaiIqXtWbjpzsPXUWYgjvN3WGC8H84Wg==', 
    b'wMf13kWD/AKeZjTIRU/ZxDgKk5WXsW728jcaVxCEnm7IlHeYsWI+EdkXLjMJmUcZ5IMPeB6K2iY=', 
    b'wMf1jFPU9AKXIzaNXgDBwDgUm5aXu2rmpjsbBAyPzSLWm2bQ5X43GtkGYTBFgksfr8wKOQCHxiY=', 
    b'wMf13kCd8AfSZSKHRADBwDRakIzQsXv6vSsaQUWElS3WiWaUsXMgEZdHNStMy0UV/NdMahWP0Ge9w/pygqSQZgMr0UeA',
    # ... additional ciphertexts for demonstration
    b'x8f13kGV5lCBYjTIXU+VwDQbjsXDsW7m8jgAVgCHgSfajiOR43N2EpgEKC1Oy00C+8oCegSHzGbzwus31qKeMAc1wFzIe3QYc1XEo/wStUfS+6cxTs4kINf3BpEKezO63jO/3EDypB0IrW5c0lY3',
    b'wMf13kKb4ALSYSWbCVfU23EKnYbcvGuypTcdTEWViCvRnGSVsXE/BpUUYStMikwT4cRMbR+Zwnq3huo6k7+DMAgizEGOc3MHd1eQuucQ8w==',
    b'2dawmlOa4RmBd3CcTEzZ23EXmcXDsW7m8j0BQRKIgymfn3GZ8n0lVJAUYTVMmVFa7cIIORaB0Siqyesg1qKUdRIvmg==',
]

def load_ciphertext_data():
    """
    Load and decode the test ciphertext data.
    
    Returns:
        list: Decoded ciphertext bytes
    """
    # Decode all base64-encoded ciphertexts
    ciphertexts = [b64decode(encoded_ct) for encoded_ct in encoded_ciphertexts]
    
    print("=== Ciphertext Analysis ===")
    print(f"Number of ciphertexts: {len(ciphertexts)}")
    
    # Analyze length distribution
    longest_ct = max(ciphertexts, key=len)
    shortest_ct = min(ciphertexts, key=len)
    
    print(f"Longest ciphertext: {len(longest_ct)} bytes")
    print(f"Shortest ciphertext: {len(shortest_ct)} bytes")
    print(f"Average length: {sum(len(ct) for ct in ciphertexts) // len(ciphertexts)} bytes")
    
    return ciphertexts

def simple_character_frequency_attack(ciphertexts):
    """
    Perform a simple character frequency attack by counting ASCII letters.
    
    This is a naive approach that counts how many valid ASCII letters
    result from each possible keystream byte guess.
    
    Args:
        ciphertexts (list): List of ciphertext bytes
        
    Returns:
        list: Candidate keystream bytes for the first position
    """
    print("\n=== Simple Character Frequency Attack ===")
    print("Attacking first byte using ASCII letter frequency...")
    
    # Count valid ASCII letters for each possible keystream byte
    counters = np.zeros(256, dtype=int)
    
    for guessed_byte in range(256):
        for ciphertext in ciphertexts:
            # XOR first byte with guessed keystream byte
            decrypted_char = chr(ciphertext[0] ^ guessed_byte)
            if decrypted_char in ascii_letters:
                counters[guessed_byte] += 1
    
    # Find the best matches
    max_matches = max(counters)
    print(f"Maximum ASCII letter matches: {max_matches}")
    
    # Create sorted list of candidates
    match_list = [(counters[i], i) for i in range(256)]
    ordered_matches = sorted(match_list, reverse=True)
    
    # Select candidates within 95% of the maximum score
    candidates = []
    for count, byte_value in ordered_matches:
        if count < max_matches * 0.95:
            break
        candidates.append((count, byte_value))
    
    print(f"Top candidates for first byte: {candidates}")
    return candidates

def statistical_frequency_attack(ciphertexts):
    """
    Perform statistical frequency analysis using English character frequencies.
    
    This more sophisticated approach uses known English character frequencies
    to score potential keystream bytes.
    
    Args:
        ciphertexts (list): List of ciphertext bytes
        
    Returns:
        bytearray: Recovered keystream
    """
    print("\n=== Statistical Frequency Attack ===")
    print("Using English character frequencies for keystream recovery...")
    
    # Find the maximum length to analyze
    max_length = max(len(ct) for ct in ciphertexts)
    min_length = min(len(ct) for ct in ciphertexts)
    
    print(f"Analyzing {max_length} keystream positions...")
    
    candidates_list = []
    
    # Analyze each keystream position
    for byte_position in range(max_length):
        # Calculate frequency scores for each possible keystream byte
        frequency_scores = np.zeros(256, dtype=float)
        
        for guessed_keystream_byte in range(256):
            total_score = 0.0
            
            # Test this keystream byte against all ciphertexts
            for ciphertext in ciphertexts:
                if byte_position >= len(ciphertext):
                    continue  # Skip if ciphertext is too short
                
                # Decrypt the byte at this position
                decrypted_byte = ciphertext[byte_position] ^ guessed_keystream_byte
                decrypted_char = chr(decrypted_byte)
                
                # Only score printable characters
                if decrypted_char in printable:
                    # Add frequency score for this character
                    char_freq = CHARACTER_FREQ.get(decrypted_char.lower(), 0)
                    total_score += char_freq
            
            frequency_scores[guessed_keystream_byte] = total_score
        
        # Sort candidates by frequency score
        scored_candidates = [(frequency_scores[i], i) for i in range(256)]
        ordered_candidates = sorted(scored_candidates, reverse=True)
        
        candidates_list.append(ordered_candidates)
        
        # Show progress for first few bytes
        if byte_position < 5:
            best_score, best_byte = ordered_candidates[0]
            print(f"Position {byte_position}: best candidate = {best_byte} (score: {best_score:.4f})")
    
    # Extract the best keystream candidate
    keystream = bytearray()
    for candidates in candidates_list:
        best_score, best_byte = candidates[0]
        keystream.append(best_byte)
    
    return keystream

def manual_keystream_refinement(keystream, ciphertexts):
    """
    Manually refine keystream bytes based on known plaintext patterns.
    
    This function demonstrates how an attacker might manually adjust
    keystream bytes when they can guess parts of the plaintext.
    
    Args:
        keystream (bytearray): Initial keystream guess
        ciphertexts (list): List of ciphertext bytes
        
    Returns:
        bytearray: Refined keystream
    """
    print("\n=== Manual Keystream Refinement ===")
    print("Refining keystream based on expected plaintext patterns...")
    
    # Example manual adjustments based on expected patterns
    # In a real attack, these would be based on context clues or guessed content
    
    # Adjust first byte (often need manual correction)
    keystream[0] = 148  # Manually set based on analysis
    
    # If we expect the first word to start with "Th" (common in English)
    if len(keystream) > 1 and len(ciphertexts[0]) > 1:
        # Calculate what keystream[1] should be for 'h'
        expected_second_char = ord('h')
        actual_decrypted = keystream[1] ^ ciphertexts[0][1]
        correction_mask = actual_decrypted ^ expected_second_char
        keystream[1] = keystream[1] ^ correction_mask
        print(f"Adjusted keystream[1] to produce 'h'")
    
    # Similar adjustment for third character
    if len(keystream) > 2 and len(ciphertexts[0]) > 2:
        # Assume third character should be 'i' (as in "This")
        expected_third_char = ord('i')
        actual_decrypted = keystream[2] ^ ciphertexts[0][2]
        correction_mask = actual_decrypted ^ expected_third_char
        keystream[2] = keystream[2] ^ correction_mask
        print(f"Adjusted keystream[2] to produce 'i'")
    
    return keystream

def decrypt_all_messages(keystream, ciphertexts):
    """
    Decrypt all ciphertexts using the recovered keystream.
    
    Args:
        keystream (bytearray): Recovered keystream
        ciphertexts (list): List of ciphertext bytes
    """
    print("\n=== Decryption Results ===")
    print("Decrypting all messages with recovered keystream:")
    print("-" * 60)
    
    for i, ciphertext in enumerate(ciphertexts):
        # Decrypt as much as possible with available keystream
        decrypt_length = min(len(keystream), len(ciphertext))
        
        try:
            # XOR ciphertext with keystream
            plaintext = strxor(ciphertext[:decrypt_length], keystream[:decrypt_length])
            
            # Attempt to decode as text
            try:
                decoded_text = plaintext.decode('utf-8', errors='replace')
                print(f"Message {i+1:2d}: {decoded_text}")
            except UnicodeDecodeError:
                print(f"Message {i+1:2d}: {plaintext.hex()} (binary)")
                
        except Exception as e:
            print(f"Message {i+1:2d}: Error - {e}")
    
    print("-" * 60)

def demonstrate_vulnerability():
    """
    Demonstrate why keystream reuse is a critical vulnerability.
    """
    print("\n=== Security Implications ===")
    print("This attack demonstrates several critical points:")
    print("1. NEVER reuse the same key/nonce combination in stream ciphers")
    print("2. Each encryption must use a unique nonce/IV")
    print("3. Stream cipher security depends entirely on keystream uniqueness")
    print("4. Multiple messages with same keystream = complete compromise")
    print("5. Modern modes like AES-GCM prevent this with proper nonce handling")

def main():
    """
    Main function demonstrating the complete keystream reuse attack.
    """
    print("=== Keystream Reuse Attack Demonstration ===")
    print("This attack exploits the reuse of the same keystream across multiple messages")
    print("Mathematical foundation: C1 ⊕ C2 = P1 ⊕ P2 (keystream cancels out)")
    
    # Load the test data
    ciphertexts = load_ciphertext_data()
    
    # Perform simple character counting attack
    simple_candidates = simple_character_frequency_attack(ciphertexts)
    
    # Perform statistical frequency analysis attack
    recovered_keystream = statistical_frequency_attack(ciphertexts)
    
    # Manually refine the keystream based on expected patterns
    refined_keystream = manual_keystream_refinement(recovered_keystream, ciphertexts)
    
    # Decrypt all messages with the recovered keystream
    decrypt_all_messages(refined_keystream, ciphertexts)
    
    # Explain the security implications
    demonstrate_vulnerability()
    
    print("\n=== Attack Summary ===")
    print(f"Successfully recovered {len(refined_keystream)} bytes of keystream")
    print("This keystream can decrypt ANY message encrypted with the same key/nonce")
    print("The attack requires only the ciphertexts - no key knowledge needed!")

if __name__ == '__main__':
    main()
