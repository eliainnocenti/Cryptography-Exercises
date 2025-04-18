import random
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes

from secret import flag, randkey  # Import the flag and a random key from the secret module

# Initialize the nonce to an invalid value
nonce = -1

def encrypt_and_update(msg, nonce):
    """
    Encrypts the given message using ChaCha20 with the provided nonce.
    Updates the nonce to a new random value after encryption.
    """
    # Create a ChaCha20 cipher with the given key and nonce
    cipher = ChaCha20.new(key=randkey, nonce=long_to_bytes(nonce))
    # Update the nonce to a new random 96-bit value
    nonce = random.getrandbits(12 * 8)
    # Encrypt the message and return the ciphertext
    return cipher.encrypt(msg.encode())

def main():
    """
    Main function to initialize the random seed, encrypt the flag,
    and allow the user to encrypt additional messages.
    """
    # Prompt the user to provide a seed for random number generation
    seed = int(input(
        "Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> "))
    random.seed(seed)  # Initialize the random number generator with the provided seed
    nonce = random.getrandbits(12 * 8)  # Generate a random 96-bit nonce

    # Encrypt and display the flag
    print("OK! I can now give you the encrypted secret!")
    print(encrypt_and_update(flag, nonce).hex())  # Encrypt the flag and print the ciphertext in hex format

    # Allow the user to encrypt additional messages
    confirm = input("Do you want to encrypt something else? (y/n)")
    while confirm.lower() != 'n':  # Continue until the user inputs 'n'
        if confirm.lower() == 'y':  # If the user wants to encrypt a message
            msg = input("What is the message? ")  # Prompt for the message
            print(encrypt_and_update(msg, nonce).hex())  # Encrypt the message and print the ciphertext in hex format
        confirm = input("Do you want to encrypt something else? (y/n)")  # Ask again if the user wants to continue

if __name__ == '__main__':
    main()  # Run the main function
