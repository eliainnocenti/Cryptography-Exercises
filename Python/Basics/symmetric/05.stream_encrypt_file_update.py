# This program encrypts the content of the file passed as the first argument
# and saves the ciphertext in the file whose name is passed as the second argument.

import base64
import sys

from Crypto.Random import get_random_bytes
from Crypto.Cipher import Salsa20

# Define a 128-bit key (16 bytes) for Salsa20.
salsa_key = b'deadbeeddeadbeef'

# Generate a random 8-byte nonce for Salsa20.
nonce = get_random_bytes(8)

# Create a Salsa20 cipher object with the key and nonce.
streamcipher = Salsa20.new(salsa_key, nonce)

# Open the output file for writing ciphertext.
f_output = open(sys.argv[2], "wb")

# Initialize an empty ciphertext variable.
ciphertext = b''

# Read the input file in chunks and encrypt each chunk.
with open(sys.argv[1], "rb") as f_input:
    plaintext = f_input.read(1024) # Read 1024 bytes at a time.
    while plaintext:
        ciphertext += streamcipher.encrypt(plaintext) # Encrypt the chunk.
        f_output.write(ciphertext) # Write the ciphertext to the output file.
        plaintext = f_input.read(1024) # Read the next chunk.

# Print the Base64-encoded nonce for decryption.
print("nonce = " + base64.b64encode(streamcipher.nonce).decode())
