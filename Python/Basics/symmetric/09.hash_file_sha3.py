from Crypto.Hash import SHA3_256

# Create a new SHA3-256 hash object.
hash_gen = SHA3_256.new()

# Open the current script file in text mode and hash its content.
with open(__file__) as f_input:
    hash_gen.update(f_input.read().encode()) # Read and encode the file content.

# Print the binary digest of the hash (raw bytes).
print(hash_gen.digest())

# Print the hexadecimal representation of the hash digest.
print(hash_gen.hexdigest())

# Create a new SHA3-256 hash object for binary mode hashing.
hash_gen = SHA3_256.new()

# Open the current script file in binary mode and hash its content.
with open(__file__, "rb") as f_input:
    hash_gen.update(f_input.read())  # Read the file content in binary mode.

# Print the binary digest of the hash (raw bytes).
print(hash_gen.digest())

# Print the hexadecimal representation of the hash digest.
print(hash_gen.hexdigest())
