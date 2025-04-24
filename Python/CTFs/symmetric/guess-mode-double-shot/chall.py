import random

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from secret import flag # Import the flag from a secret module

# Mapping of mode names to AES mode constants
modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}

class RandomCipherRandomMode():
    """
    A class that initializes an AES cipher with a random mode (ECB or CBC).
    Generates a random key and, if using CBC mode, a random IV.
    """
    def __init__(self):
        # Randomly choose between ECB and CBC modes
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        self.mode = random.choice(modes)
        self.key = get_random_bytes(32) # Generate a random 256-bit key

        if self.mode == AES.MODE_ECB:
            self.iv = None # ECB mode does not use an IV
            self.cipher = AES.new(key=self.key, mode=self.mode) # Create an AES cipher in ECB mode
        else:
            self.iv = get_random_bytes(16) # Generate a random 128-bit IV for CBC mode
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode) # Create an AES cipher in CBC mode

    def encrypt(self, data):
        """
        Encrypts the given data using the initialized cipher.
        """
        return self.cipher.encrypt(data)

    def decrypt(self, data):
        """
        Decrypts the given data using the initialized cipher.
        """
        return self.cipher.decrypt(data)

def main():
    """
    Main function to run the challenge.
    The user must correctly guess the encryption mode (ECB or CBC) for 128 challenges.
    """
    for i in range(128): # Loop through 128 challenges
        cipher = RandomCipherRandomMode() # Initialize a cipher with a random mode

        print(f"Challenge #{i}") # Display the challenge number

        data = b"\00" * 32 # Create a 32-byte block of zeros as the initial data
        otp = get_random_bytes(len(data)) # Generate a one-time pad of the same length as the data

        for _ in range(2): # Allow the user to provide input twice
            data = bytes.fromhex(input("Input: ").strip()) # Get user input in hex format and convert to bytes
            if len(data) != 32: # Ensure the input is exactly 32 bytes
                print("Data must be 32 bytes long")
                return

            # XOR the user-provided data with the one-time pad
            data = bytes([d ^ o for d, o in zip(data, otp)])
            # Encrypt the XORed data and print the ciphertext in hex format
            print(f"Output: {cipher.encrypt(data).hex()}")

        # Prompt the user to guess the encryption mode
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        # Check if the user's guess matches the actual mode
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next") # Correct guess
        else:
            print("Wrong, sorry") # Incorrect guess
            return

    # If the user successfully completes all challenges, print the flag
    print(f"The flag is: {flag}")

if __name__ == "__main__":
    main() # Run the main function
