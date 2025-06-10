from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

# Generate two random 512-bit primes for RSA modulus
p, q = getPrime(512), getPrime(512)
n = p*q   # RSA modulus
e = 65537 # Common public exponent

# Convert the flag to a long integer for encryption
m = bytes_to_long(flag.encode())

# Print the ciphertext of the flag (RSA encryption)
print(pow(m, e, n))

# Allow the user to interact with the encryption/decryption oracle 3 times
for _ in range(3):
    req = input()
    if req[0] == 'e':
        # Encrypt the provided number with the public key
        print(pow(int(req[1:]), e, n))
    elif req[0] == 'd':
        # Decrypt the provided number with the private key
        phi = (p-1)*(q-1)   # Euler's totient for n
        d = inverse(e, phi) # Private exponent
        dec = pow(int(req[1:]), d, n)
        assert dec != m # Prevent decryption of the flag itself
        print(dec)
