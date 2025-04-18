# An encryption oracle, listening on IP:port, receives as input a string and
# returns another string that encodes in hexadecimal the result of the
# encryption with AES in ECB mode of the following plaintext
# message = """Here is the msg:{0} - and the sec:{1}""".format( input, secret)
# where input is the string received as input and secret is
# a secret string, composed of 16 printable characters
# Complete the program so that the secret is discovered without brute forcing
# the whole search space

import string
from pwn import *

from Crypto.Cipher import AES

from myconfig import HOST, PORT

SECRET_LEN = 16 # Length of the secret string to be discovered
secret = ""     # Variable to store the discovered secret

# 0:15  Here is the msg:
# 16:31 {0}
# 32:47
# 48:63 - and the key:s0
# 64:79 s1 .. s15 pad

# HEX STRING
# 0:31    Here is the msg:
# 32:63   {0}
# 64:95   {0} ...continued
# 96:127  - and the key:s0
# 128:139 s1 .. s15 pad

# HEX STRING
# 0:31    Here is the msg:
# 32:63   - and the key:X
# 64:95   pad --> starts from one block, decreases at each letter discovered
# 96:127  - and the key:s0
# 128:139 s1 .. s15 pad

# message = """Here is the msg:{0} - and the key:{1}""".format( input0, ecb_oracle_secret)

# The fixed part of the message that precedes the secret
fix = " - and the sec:"

# Loop through each character position in the secret
for i in range(0, SECRET_LEN):
    # Create padding to align the secret character at the end of a block
    pad = "A" * (AES.block_size - i)
    for letter in string.printable: # Iterate through all printable characters
        server = remote(HOST, PORT) # Connect to the encryption oracle

        # Construct the message with the guessed character
        msg = fix + secret + letter + pad
        print("Sending: " + msg)
        server.send(msg) # Send the message to the server
        ciphertext = server.recv(1024) # Receive the ciphertext

        server.close() # Close the connection

        # Compare the relevant ciphertext blocks to check if the guess is correct
        if ciphertext[16:32] == ciphertext[48:64]:
            print("Found new character = " + letter)
            secret += letter # Append the discovered character to the secret
            fix = fix[1:] # Adjust the fixed part to maintain alignment
            break

print("Secret discovered = " + secret) # Print the discovered secret
