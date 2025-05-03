import os
from Crypto.Cipher import ChaCha20

# Generate a random 256-bit key for ChaCha20 encryption
key = os.urandom(32)

# Generate a random 96-bit nonce for ChaCha20 encryption
nonce = os.urandom(12)

# Print the key and nonce in hex format for debugging purposes
print(f"Using key: {key.hex()}, nonce: {nonce.hex()}")

# Open the input file containing the plaintext message
with open("./hacker-manifesto.txt") as f:
    lines = f.readlines() # Read all lines from the file

enc = []  # Initialize a list to store the encrypted lines

# Encrypt each line of the plaintext file
for line in lines:
    # Create a new ChaCha20 cipher with the same key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # Encrypt the line and append the ciphertext (in hex format) to the list
    enc.append(cipher.encrypt(line.encode()).hex())

# Write the encrypted lines to the output file
with open("./hacker-manifesto.enc", "w") as f:
    f.write("\n".join(enc)) # Join the encrypted lines with newlines and write to the file
