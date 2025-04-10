from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# Define a password to derive the key from.
password = b'W34kpassw0rd!'
print(f"Password: {password.decode()}")

# Generate a random 16-byte salt.
salt = get_random_bytes(16)

# A good choice of parameters (N, r , p) was suggested by Colin Percival in his presentation in 2009:
# http://www.tarsnap.com/scrypt/scrypt-slides.pdf
# ( 2¹⁴, 8, 1 ) for interactive logins (≤100ms)
# ( 2²⁰, 8, 1 ) for file encryption (≤5s)

key = scrypt(password, salt, 16, N = 2**14, r = 8, p = 1)

# Print the salt (must be stored for key derivation).
print(f"Salt (store securely for key derivation): {salt.hex()}")

# Print the derived key (should remain secret).
print("This should be secret: " + str(key))
