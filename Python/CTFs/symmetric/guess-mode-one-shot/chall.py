# see note info on smartphone

import random

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from secret import flag # Import the flag from a secret module

# Mapping of mode names to PyCryptodome constants
modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}

class RandomCipherRandomMode():
    """
    A class that generates a random AES cipher in either ECB or CBC mode.
    """
    def __init__(self):
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes) # Randomly choose ECB or CBC
        self.key = get_random_bytes(32)  # Generate a random 256-bit key
        if self.mode == AES.MODE_ECB:
            self.iv = None
            self.cipher = AES.new(key=self.key, mode=self.mode)
        else:
            self.iv = get_random_bytes(16) # Generate a random IV for CBC
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)

    def encrypt(self, data):
        """
        Encrypts the given data using the chosen cipher.
        """
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        """
        Decrypts the given data using the chosen cipher.
        """
        return self.cipher.decrypt(data)

def main():
    """
    Main function to simulate the challenge server.
    """
    for i in range(128): # Allow up to 128 challenges
        cipher = RandomCipherRandomMode() # Create a random cipher

        print(f"Challenge #{i}")

        otp = get_random_bytes(32) # Generate a random OTP
        print(f"The otp I'm using: {otp.hex()}")
        data = bytes.fromhex(input("Input: ").strip()) # Receive input from the user
        if len(data) != 32: # Ensure the input is 32 bytes long
            print("Data must be 32 bytes long")
            return

        # XOR the input with the OTP
        data = bytes([d ^ o for d, o in zip(data, otp)])
        print(f"Output: {cipher.encrypt(data).hex()}") # Encrypt and output the result

        # Ask the user to guess the mode
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next") # Correct guess
        else:
            print("Wrong, sorry") # Incorrect guess
            return

    print(f"The flag is: {flag}") # Print the flag if all challenges are passed

if __name__ == "__main__":
    main()
