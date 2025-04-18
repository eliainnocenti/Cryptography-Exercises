import os
import string
from math import ceil
from pwn import *

from Crypto.Cipher import AES

# Configure pwntools to work in IDE environments
os.environ['PWNLIB_NOTERM'] = 'True' # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from myconfig import HOST, PORT

if __name__ == '__main__':
    # server = remote(HOST,PORT)
    # message = b"A"*10
    # server.send(message)
    # ciphertext = server.recv(1024)
    # server.close()
    # print(ciphertext.hex())
    # print(len(ciphertext))

    # message = """Here is the msg:{0} - and the sec:{1}""".format(input0, ecb_oracle_secret)

    # Prefix and postfix are fixed parts of the message
    prefix = b'Here is the msg:'
    postfix = b' - and the sec:'
    print(len(prefix))  # Print the length of the prefix
    print(len(postfix)) # Print the length of the postfix

    # for guess in string.printable:
    #     message = postfix + guess.encode()
    #     full_string = prefix + message + postfix + b'?'
    #     print(full_string)
    #     for i in range(ceil(len(full_string)/AES.block_size)):
    #         print(full_string[i*16:(i+1)*16])

    # Discover the first character of the secret
    for guess in string.printable:
        message = postfix + guess.encode() # Append the guessed character
        server = remote(HOST, PORT)        # Connect to the encryption oracle
        server.send(message)               # Send the message
        ciphertext = server.recv(1024)     # Receive the ciphertext
        server.close()                     # Close the connection

        # Compare ciphertext blocks to verify the guess
        if ciphertext[16:32] == ciphertext[32:48]:
            print("Found 1st char=" + guess)
            break

    # for guess in string.printable:
    #     message = postfix[1:] + b'H' + guess.encode() + b'A'*(AES.block_size-1)
    #     full_string = prefix + message + postfix + b'??'
    #     print(full_string)
    #     for i in range(ceil(len(full_string)/AES.block_size)):
    #         print(full_string[i*16:(i+1)*16])

    # Discover the entire secret
    secret = b''
    for i in range(AES.block_size):       # Loop through each character position
        pad = (AES.block_size - i) * b'A' # Create padding for alignment
        for guess in string.printable:    # Iterate through all printable characters
            message = postfix + secret + guess.encode() + pad
            print(message)

            server = remote(HOST, PORT)    # Connect to the encryption oracle
            server.send(message)           # Send the message
            ciphertext = server.recv(1024) # Receive the ciphertext
            server.close()                 # Close the connection

            # Compare ciphertext blocks to verify the guess
            if ciphertext[16:32] == ciphertext[48:64]:
                print("Found=" + guess)
                secret += guess.encode() # Append the discovered character
                postfix = postfix[1:]    # Adjust the postfix for alignment
                break
    
    print(secret) # Print the discovered secret
