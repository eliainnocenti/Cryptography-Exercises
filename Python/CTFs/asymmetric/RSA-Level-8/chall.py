from Crypto.Util.number import bytes_to_long, getPrime # Import functions for number conversion and prime generation
from secret import flag # Import the secret flag from another file

# Generate three random 512-bit primes and compute their products
n1 = getPrime(512)*getPrime(512) # For n1
n2 = getPrime(512)*getPrime(512) # For n2
n3 = getPrime(512)*getPrime(512) # For n3

n = [n1, n2, n3] # Store the three moduli in a list
print(n) # Output the list of moduli

e = 3 # Set the public exponent e to 3 (small exponent)
m = bytes_to_long(flag.encode()) # Convert the flag string to a long integer

# Encrypt the message m with each modulus and print the list of ciphertexts
print([pow(m, e, nn) for nn in n])
