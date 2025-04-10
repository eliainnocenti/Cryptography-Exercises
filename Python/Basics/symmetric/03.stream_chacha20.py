import base64
import sys

from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20

# Define the plaintext message to encrypt.
plaintext = b'This is the secret message to encrypt'

# Generate a random 256-bit key for ChaCha20.
key = get_random_bytes(ChaCha20.key_size)

# Create a ChaCha20 cipher object with an automatically generated nonce.
cipher = ChaCha20.new(key=key)

# Alternative code if you want to select the nonce explicitly:
# nonce = get_random_bytes(12)
# cipher = ChaCha20.new(nonce=nonce, key=key)

# Encrypt the plaintext message.
ciphertext = cipher.encrypt(plaintext)

# Print the Base64-encoded ciphertext for readability.
print(f"Base64-encoded ciphertext: {base64.b64encode(ciphertext).decode()}")

# Print the Base64-encoded nonce for decryption.
print(f"Base64-encoded nonce (required for decryption): {base64.b64encode(cipher.nonce).decode()}")

# Compare memory sizes of plaintext and ciphertext.
print(f"Memory size of plaintext: {sys.getsizeof(plaintext)} bytes")
print(f"Memory size of ciphertext: {sys.getsizeof(ciphertext)} bytes")

# Print the length of the nonce (12 bytes for ChaCha20).
print(f"Length of nonce: {len(cipher.nonce)} bytes")
