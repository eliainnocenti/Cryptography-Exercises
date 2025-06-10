import os
import random
from time import time
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
from secret import flag

# Generate a random 32-byte key for ChaCha20
key = os.urandom(32)

def encrypt(msg):
    # Seed the random number generator with the current time (seconds)
    random.seed(int(time()))
    # Generate a random 12-byte nonce for ChaCha20
    cipher = ChaCha20.new(
        key=key, nonce=long_to_bytes(random.getrandbits(12*8)))
    # Encrypt the message and return ciphertext
    return cipher.encrypt(msg.encode())

def main():
    # Simple menu for user interaction
    confirm = input("Want to encrypt? (y/n/f)")
    while confirm.lower() != 'n':
        if confirm.lower() == 'y':
            # Encrypt user-provided message
            msg = input("> ")
            print(encrypt(msg).hex())
        elif confirm.lower() == 'f':
            # Encrypt the flag
            print(encrypt(flag).hex())
        confirm = input("Want to encrypt something else? (y/n/f)")

if __name__ == '__main__':
    main()
