import base64
import json

from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA512

# Define the message to compute the HMAC for.
msg = b'This is the message to use. Now compute the SHA512-HMAC'

# Generate a random 256-bit secret key.
secret = get_random_bytes(32)
print(f"Generated secret key (256-bit): {base64.b64encode(secret).decode()}")

# Create an HMAC object using the secret key and SHA512 as the hash function.
hmac_gen = HMAC.new(secret, digestmod=SHA512)

# Update the HMAC object with parts of the message.
hmac_gen.update(msg[:10]) # First part of the message.
hmac_gen.update(msg[10:]) # Remaining part of the message.

# Compute the HMAC and store it as a hexadecimal string.
mac = hmac_gen.hexdigest()
print(f"Computed HMAC (SHA512): {mac}")

# Store the message and HMAC in a JSON object.
json_dict = {"message": msg.decode(), "MAC": mac}
json_object = json.dumps(json_dict)
print(f"JSON object: {json_object}")

# ASSUMPTION: The secret key has been securely exchanged.

# Deserialize the JSON object and extract the message and HMAC.
b64 = json.loads(json_object)

# Create a new HMAC object for verification using the same secret key.
hmac_ver = HMAC.new(secret, digestmod=SHA512)

# Update the HMAC object with the received message.
hmac_ver.update(b64["message"].encode())

# Verify the received HMAC against the computed HMAC.
try:
    hmac_ver.hexverify(b64["MAC"])
    print(f"The message '{msg.decode()}' is authentic.")
except ValueError:
    print("HMAC verification failed: Wrong secret or message.")
