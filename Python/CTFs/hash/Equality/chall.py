from Crypto.Hash import MD4    # Import the MD4 hash implementation from PyCryptodome
import hashlib                 # Import hashlib for MD5 hashing
from binascii import unhexlify # Import unhexlify to convert hex input to bytes
from secret import flag        # Import the secret flag from another file

def md4(data: bytes) -> str:
    # Compute the MD4 hash of the input data and return its hexadecimal representation
    h = MD4.new()
    h.update(data)
    return h.hexdigest()

print("Find two strings that are both equal and different! I'll use _optimized algorithms_ to check.")

s1 = unhexlify(input("Enter the first string: "))   # Read the first input as hex and convert to bytes
s2 = unhexlify(input("Enter your second string: ")) # Read the second input as hex and convert to bytes

md4_s1 = md4(s1) # Compute MD4 hash of the first input
md4_s2 = md4(s2) # Compute MD4 hash of the second input

md5_s1 = hashlib.md5(s1).hexdigest() # Compute MD5 hash of the first input
md5_s2 = hashlib.md5(s2).hexdigest() # Compute MD5 hash of the second input

# Check if the MD4 hashes are equal but the MD5 hashes are different
if md4_s1 == md4_s2 and md5_s1 != md5_s2:
    print(f"Good job! {flag}") # If so, print the flag
else:
    print("Try again!")        # Otherwise, prompt to try again
