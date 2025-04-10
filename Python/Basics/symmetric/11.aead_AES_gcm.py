from base64 import b64encode, b64decode
import json

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

# Define the header (authenticated but not encrypted) and the data (encrypted).
header = b"this is the authentication only part"
data = b"this is the secret part"

# Generate a random 256-bit AES key.
key = get_random_bytes(AES.key_size[2])

# Create an AES cipher object in GCM mode.
cipher = AES.new(key, AES.MODE_GCM)

# Add the header to the cipher for authentication.
cipher.update(header)

# Encrypt the data and compute the authentication tag.
ciphertext, tag = cipher.encrypt_and_digest(data)

# Serialize the nonce, header, ciphertext, and tag into a JSON object.
json_k = ['nonce', 'header', 'ciphertext', 'tag']
outputs = [cipher.nonce, header, ciphertext, tag]
json_v = [b64encode(x).decode() for x in outputs]
json_object = json.dumps(dict(zip(json_k, json_v)))
print(f"Serialized JSON object (nonce, header, ciphertext, tag): {json_object}")

# Deserialize the JSON object and decode the Base64-encoded values.
try:
    b64 = json.loads(json_object)
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    jv = {k: b64decode(b64[k]) for k in json_k}

    # Create a new AES cipher object for decryption using the received nonce.
    cipher_receiver = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])

    # Add the received header for authentication.
    cipher_receiver.update(jv['header'])

    # Decrypt the ciphertext and verify the authentication tag.
    plaintext = cipher_receiver.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    print(f"Decoded plaintext: {plaintext.decode('utf-8')}")
    print("The message is authentic and was decrypted successfully.")
except (ValueError, KeyError):
    print("Decryption failed: Incorrect decryption or authentication tag mismatch.")
