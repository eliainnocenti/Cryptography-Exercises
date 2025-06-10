from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

# Generate two random 64-bit prime numbers for RSA key generation
p, q = getPrime(64), getPrime(64)

# Compute the RSA modulus n as the product of the two primes
n = p * q

# Set the public exponent e to 65537, a common choice in RSA
e = 65537

print(n)  # Output the modulus n (public key component)

# Convert the flag (a byte string) to a long integer for encryption
m = bytes_to_long(flag)

# Encrypt the message m using RSA: c = m^e mod n, and print the ciphertext
print(pow(m, e, n))

# The following are example outputs for n and the ciphertext, respectively:
# 176278749487742942508568320862050211633
# 46228309104141229075992607107041922411
