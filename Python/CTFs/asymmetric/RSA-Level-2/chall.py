from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from secret import flag

def next_prime(p):
    # Find the next prime greater than p
    while True:
        p = p+1
        if isPrime(p):
            return p

p = getPrime(512) # Generate a random 512-bit prime number for p
q = next_prime(p) # Find the next prime after p for q
n = p*q           # Compute the RSA modulus n as the product of p and q
e = 65537         # Set the public exponent e to 65537 (common choice)
print(n)          # Output the modulus n

m = bytes_to_long(flag.encode()) # Convert the flag string to a long integer
print(pow(m, e, n)) # Encrypt the message m using RSA and print the ciphertext
