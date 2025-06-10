from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag

# Generate two random 512-bit primes for RSA modulus
p, q = getPrime(512), getPrime(512)
n = p*q # RSA modulus

print(n) # Output the modulus

# Use a fixed large public exponent
e = 60016485563460433620911462871489753027091796150597697863772440338904706321535832359517415034149374289955681381097544059467926029963755494161141305994584249448583991034102694954139120453335603006006970009433124857766494518747385902016093339683987307620366742481560543776055295663835860818720290861634213881385

# Convert the flag to a long integer for encryption
m = bytes_to_long(flag.encode())

# Print the ciphertext of the flag (RSA encryption)
print(pow(m, e, n))
