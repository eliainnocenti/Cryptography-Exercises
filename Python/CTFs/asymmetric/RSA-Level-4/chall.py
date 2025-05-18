from Crypto.Util.number import bytes_to_long, getPrime # Import functions for number conversion and prime generation
from secret import flag # Import the secret flag from another file

p, q = getPrime(512), getPrime(512) # Generate two random 512-bit prime numbers for p and q
n = p*q      # Compute the RSA modulus n as the product of p and q
e = [31, 71] # Define a list of two public exponents to be used
print(n)     # Output the modulus n

m = bytes_to_long(flag.encode())   # Convert the flag string to a long integer
print([pow(m, ee, n) for ee in e]) # Encrypt the message m with each exponent and print the list of ciphertexts
