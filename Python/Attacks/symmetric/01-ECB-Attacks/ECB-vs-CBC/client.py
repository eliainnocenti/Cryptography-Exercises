import os
os.environ['PWNLIB_NOTERM'] = 'True' # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from math import ceil
from Crypto.Cipher import AES

from myconfig import HOST, PORT

# AES block size in bytes
BLOCK_SIZE = AES.block_size
# AES block size in hexadecimal representation
BLOCK_SIZE_HEX = 2 * BLOCK_SIZE

# Connect to the server
server = remote(HOST, PORT)

# stole from the server code...

# Define the structure of the server's response
# message = "This is what I received: " + msg + " -- END OF MESSAGE"
start_str = "This is what I received: "

# print(len(start_str))

# Calculate the padding length to align with the block size
pad_len = ceil(len(start_str) / BLOCK_SIZE) * BLOCK_SIZE - len(start_str)

# Construct the message to send (2 blocks of 'A' + padding)
msg = b"A" * (16 * 2 + pad_len) # 2 * AES.block_size + pad_len
print("Sending: " + str(msg))
server.send(msg)

# Receive the ciphertext from the server
ciphertext = server.recv(1024)
ciphertext_hex = ciphertext.hex()
print("Ciphertext (hex): ")
print(ciphertext_hex)

# Close the connection
server.close()

# Print the ciphertext in blocks
print("Ciphertext blocks:")
for i in range(0, int(len(ciphertext_hex) // BLOCK_SIZE_HEX)):
    print(ciphertext_hex[i * BLOCK_SIZE_HEX:(i + 1) * BLOCK_SIZE_HEX])

# Determine the encryption mode based on ciphertext patterns
print("Selected mode is", end=' ')
if ciphertext[2 * BLOCK_SIZE:3 * BLOCK_SIZE] == ciphertext[3 * BLOCK_SIZE:4 * BLOCK_SIZE]:
    print("ECB")
else:
    print("CBC")
