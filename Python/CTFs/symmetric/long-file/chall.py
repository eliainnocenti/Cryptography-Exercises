import os
from Crypto.Cipher import ChaCha20

# Generate a random 32-byte key and 12-byte nonce for ChaCha20
key = os.urandom(32)
nonce = os.urandom(12)
print(f"Using key: {key.hex()}, nonce: {nonce.hex()}")

# Read the plaintext data from a file
with open("./bigfile.txt", "r") as f:
    data = f.read().encode()

KEYSTREAM_SIZE = 1000 # Size of each keystream chunk

# Initialize ChaCha20 cipher
cipher = ChaCha20.new(key=key, nonce=nonce)

# Generate a keystream by encrypting zero bytes
keystream = bytes([x ^ y for x, y in zip(
    b"\00"*KEYSTREAM_SIZE, cipher.encrypt(b"\00"*KEYSTREAM_SIZE))])

print(len(data)) # Output the length of the data

# Encrypt the file in chunks using the generated keystream
with open("./file.enc", "wb") as f:
    for i in range(0, len(data), KEYSTREAM_SIZE):
        f.write(
            bytes([p ^ k for p, k in zip(data[i:i+KEYSTREAM_SIZE], keystream)]))
