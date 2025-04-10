import base64

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Print available AES key sizes.
print(f"Available AES key sizes: {AES.key_size}") # [16, 24, 32] - AES supports 128-bit, 192-bit, and 256-bit keys.
print(f"Selected AES key size (256-bit): {AES.key_size[2]} bytes") # 32 bytes (256-bit key).

# Generate a random AES key and initialization vector (IV).
key = get_random_bytes(AES.key_size[2]) # 256-bit key.
iv = get_random_bytes(AES.block_size)   # 16-byte IV.

# Encrypt data without padding (aligned data).
data = b'These data are to be encrypted!!'  # 32 bytes, no padding needed.
print(len(data))                            # Print length of the data.
cipher_enc = AES.new(key, AES.MODE_CBC, iv) # Create AES cipher in CBC mode.
ct = cipher_enc.encrypt(data)               # Encrypt the data.
print(f"Ciphertext length (aligned data): {len(ct)} bytes") # Print length of the ciphertext.

# Decrypt the ciphertext and verify the result.
cipher_dec = AES.new(key, AES.MODE_CBC, iv) # Create AES cipher for decryption.
pt = cipher_dec.decrypt(ct)                 # Decrypt the ciphertext.
print(pt)                                   # Print the decrypted plaintext.

# Encrypt data with padding (unaligned data).
data = b'Unaligned data to cipher'          # 24 bytes, requires padding.
cipher_enc = AES.new(key, AES.MODE_CBC, iv) # Create AES cipher in CBC mode.
padded_data = pad(data, AES.block_size)     # Pad the data to match the block size.
print(padded_data)                          # Print the padded data.
ct = cipher_enc.encrypt(padded_data)        # Encrypt the padded data.

# Print Base64-encoded ciphertext for readability.
print(f"Base64-encoded ciphertext (padded data): {base64.b64encode(ct).decode()}")

# Decrypt the ciphertext and remove padding.
cipher_dec = AES.new(key, AES.MODE_CBC, iv) # Create AES cipher for decryption.
decrypted_data = cipher_dec.decrypt(ct)     # Decrypt the ciphertext.
print(f"Decrypted data (still padded): {decrypted_data}") # Print the decrypted data (still padded).
pt = unpad(decrypted_data, AES.block_size)  # Remove padding.
print(f"Decrypted plaintext (after unpadding): {pt.decode('utf-8')}") # Print the decrypted plaintext.
assert(data == pt)                          # Verify that the original data matches the decrypted data.
