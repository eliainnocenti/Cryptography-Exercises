from Crypto.Util.number import bytes_to_long, getPrime
from secret import flag
import numpy as np

primes = [getPrime(512) for _ in range(10)] # Generate a list of 10 random 512-bit prime numbers
mods = [np.random.choice(primes, 2, replace=False) for _ in range(6)] # Randomly select 2 distinct primes for each of 6 moduli
mods = [m[0]*m[1] for m in mods] # Compute the modulus for each pair as their product
e = 65537 # Set the public exponent e to 65537 (common choice)
print(mods) # Output the list of moduli

m = bytes_to_long(flag.encode())    # Convert the flag string to a long integer
print([pow(m, e, n) for n in mods]) # Encrypt the message m with each modulus and print the list of ciphertexts
