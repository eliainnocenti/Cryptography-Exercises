import base64
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import ChaCha20

# Define the plaintext message to encrypt.
plaintext = b'This is the secret message to encrypt'

# Generate a random 256-bit key and 96-bit nonce for ChaCha20.
key = get_random_bytes(32)
nonce = get_random_bytes(12)

# Create a ChaCha20 cipher object with the key and nonce.
cipher = ChaCha20.new(key=key, nonce=nonce)

# Encrypt the plaintext message.
ciphertext = cipher.encrypt(plaintext)

# Encode the nonce and ciphertext in Base64 and store them in a JSON object.
nonceb64 = base64.b64encode(cipher.nonce).decode()
ciphertextb64 = base64.b64encode(ciphertext).decode()
result = json.dumps({'nonce': nonceb64, 'ciphertext': ciphertextb64})
print(f"Serialized JSON object (nonce and ciphertext): {result}")

# Deserialize the JSON object and decode the Base64-encoded values.
b64 = json.loads(result)
ciphertext2 = base64.b64decode(b64['ciphertext'])
nonce2 = base64.b64decode(b64['nonce'])

# Print the decoded nonce to verify correctness.
print(f"Decoded nonce (required for decryption): {nonce2}")
print(f"Original nonce: {nonce}")

# Decrypt the ciphertext using the same key and nonce.
cipher_dec = ChaCha20.new(key=key, nonce=nonce2)
plaintext_dec = cipher_dec.decrypt(ciphertext2)

# Smarter use of JSON objects even more useful when more data are saved:
# json_k = [ 'nonce', 'ciphertext']
# json_v = [ base64.b64encode(x).decode() for x in (cipher.nonce, ciphertext) ]
# result2 = json.dumps(dict(zip(json_k, json_v)))
# print(result2)
#
# b64 = json.loads(result2)
# json_k = [ 'nonce', 'ciphertext']
# jv = {k:base64.b64decode(b64[k]) for k in json_k}
#
# cipher_dec = ChaCha20.new(secret=secret,nonce=jv['nonce'])
# plaintext_dec = cipher_dec.decrypt(jv['ciphertext'])

# print(plaintext_dec)
print(f"Decoded plaintext: {plaintext_dec.decode('utf-8')}")
