# This program encrypts the content of the file passed as the first argument
# and saves the ciphertext in the file whose name is passed as the second argument.

import sys

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Generate a random 128-bit AES key (16 bytes).
aes_key = get_random_bytes(AES.key_size[0])

# Generate a random initialization vector (IV) for AES.
iv = get_random_bytes(AES.block_size)

# Create an AES cipher object in CBC mode with the key and IV.
cipher = AES.new(aes_key, AES.MODE_CBC, iv)

# Open the input file for reading in binary mode.
f_input = open(sys.argv[1], "rb")

# Read the file content, pad it to match the AES block size, and encrypt it.
ciphertext = cipher.encrypt(pad(f_input.read(), AES.block_size))

# Open the output file for writing the ciphertext in binary mode.
f_output = open(sys.argv[2], "wb")
f_output.write(ciphertext) # Write the ciphertext to the output file.

# Print the IV, which must be shared for decryption.
print(iv)
