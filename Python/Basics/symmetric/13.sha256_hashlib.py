import hashlib

# Create a new SHA-256 hash object.
digest_object = hashlib.sha256()

# Update the hash object with the first part of the message.
digest_object.update(b"First sentence to hash")
print("Updated hash object with the first part of the message.")

# Update the hash object with the second part of the message.
digest_object.update(b" and second sentence to hash.")
print("Updated hash object with the second part of the message.")

# Print the binary digest of the hash (raw bytes).
print(f"Binary digest of the hash: {digest_object.digest()}")

# Print the hexadecimal representation of the hash digest.
print(f"Hexadecimal digest of the hash: {digest_object.hexdigest()}")
