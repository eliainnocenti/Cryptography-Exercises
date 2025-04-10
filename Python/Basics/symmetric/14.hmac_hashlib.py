import hashlib
import hmac

from Crypto.Random import get_random_bytes

# Define the message to compute the HMAC for.
msg = b'This is the message'

# Generate a random 256-bit secret key.
secret = get_random_bytes(32)
print(f"Generated secret key (256-bit): {secret.hex()}")

# Create a BLAKE2b hash object with the secret key.
blake = hashlib.blake2b(key=secret, digest_size=32)

# Update the hash object with the message.
blake.update(msg)

# Print the hexadecimal representation of the BLAKE2b hash.
print("BLAKE = " + blake.hexdigest())

# Sender computes the HMAC using the secret key and SHA-256.
mac_factory = hmac.new(secret, msg, hashlib.sha256)
hmac_sha256 = mac_factory.digest()

# Print the hexadecimal representation of the HMAC.
print("HMAC-SHA256@SENDER   = " + mac_factory.hexdigest())

# Receiver receives the message and HMAC, then verifies the HMAC.
msg1 = b'This is the new message' # Simulate a modified message.
mac_factory_receiver = hmac.new(secret, msg1, hashlib.sha256)
hmac_sha256_1 = mac_factory_receiver.hexdigest()

# Print the HMAC computed by the receiver.
print("HMAC-SHA256@RECEIVER = " + hmac_sha256_1)

# Compare the received HMAC with the computed HMAC.
if hmac.compare_digest(mac_factory_receiver.digest(), hmac_sha256):
    print("HMAC correctly verified: messages are identical")
else:
    print("HMAC verification failed: messages are different")
