from Crypto.Util.number import bytes_to_long, getPrime, inverse # Import functions for number conversion, prime generation, and modular inverse
from secret import flag # Import the secret flag from another file

p, q = getPrime(512), getPrime(512) # Generate two random 512-bit prime numbers for p and q
n = p*q   # Compute the RSA modulus n as the product of p and q
e = 65537 # Set the public exponent e to 65537 (common choice)
print(n)  # Output the modulus n

m = bytes_to_long(flag.encode()) # Convert the flag string to a long integer
print(pow(m, e, n)) # Encrypt the message m using RSA and print the ciphertext

phi = (p-1)*(q-1)   # Compute Euler's totient function for n
d = inverse(e, phi) # Compute the private exponent d

while True: # Start an infinite loop to process user requests
    req = input() # Read a ciphertext from the user
    dec = pow(int(req), d, n) # Decrypt the provided ciphertext
    print(dec % 2) # Output the least significant bit (parity) of the decrypted message
