from Crypto.Cipher import Salsa20

# Define a 128-bit key (16 bytes) for Salsa20.
key = b'deadbeefdeadbeef'

# Create a Salsa20 cipher object with an automatically generated nonce.
cipher = Salsa20.new(key)

# Incrementally encrypt parts of the message.
ciphertext = cipher.encrypt(b'The first part of the secret message. ')
ciphertext += cipher.encrypt(b'The second part of the message.')

# Print the nonce, which must be shared for decryption.
nonce = cipher.nonce
print(f"Generated nonce (required for decryption): {nonce}")

# Decrypt the ciphertext using the same key and nonce.
cipher2 = Salsa20.new(key, nonce)
plaintext = cipher2.decrypt(ciphertext)

# Print the decrypted plaintext to verify correctness.
print(f"Decrypted plaintext: {plaintext.decode('utf-8')}")
