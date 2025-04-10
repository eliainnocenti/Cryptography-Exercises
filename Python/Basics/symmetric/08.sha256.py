from Crypto.Hash import SHA256

# Create a new SHA256 hash object.
hash_object = SHA256.new()

# Update the hash object with the first part of the message.
hash_object.update(b'Beginning of the message to hash...')

# Update the hash object with the second part of the message.
hash_object.update(b'...and some more data')

# Print the binary digest of the hash (raw bytes).
print(f"Binary digest of the hash (first computation): {hash_object.digest()}")

# Print the hexadecimal representation of the hash digest.
print(f"Hexadecimal digest of the hash (first computation): {hash_object.hexdigest()}")

# Create a new SHA256 hash object with an initial message.
hash_object = SHA256.new(data=b'First part of the message. ')

# Update the hash object with additional parts of the message.
hash_object.update(b'Second part of the message. ')
hash_object.update(b'Third and last.')

# Print the binary digest of the hash (raw bytes).
print(f"Binary digest of the hash (second computation): {hash_object.digest()}")

# Print the hexadecimal representation of the hash digest.
print(f"Hexadecimal digest of the hash (second computation): {hash_object.hexdigest()}")
