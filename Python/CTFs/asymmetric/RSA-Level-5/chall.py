from Crypto.Util.number import bytes_to_long, getPrime, inverse # Import functions for number conversion, prime generation, and modular inverse
from secret import flag # Import the secret flag from another file

p, q = getPrime(512), getPrime(512) # Generate two random 512-bit prime numbers for p and q
n = p*q   # Compute the RSA modulus n as the product of p and q
e = 65537 # Set the public exponent e to 65537 (common choice)
print(n)  # Output the modulus n

m = bytes_to_long(flag.encode()) # Convert the flag string to a long integer
print(pow(m, e, n)) # Encrypt the message m using RSA and print the ciphertext

req = input() # Read a request from the user

if req[0] == 'e': # If the request starts with 'e', perform encryption
    print(pow(int(req[1:]), e, n)) # Encrypt the provided integer and print the result
elif req[0] == 'd':     # If the request starts with 'd', perform decryption
    phi = (p-1)*(q-1)   # Compute Euler's totient function for n
    d = inverse(e, phi) # Compute the private exponent d
    dec = pow(int(req[1:]), d, n) # Decrypt the provided integer
    assert dec != m # Ensure the decrypted value is not the original message
    print(dec)      # Print the decrypted value
