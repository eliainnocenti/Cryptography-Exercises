from random import randint

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from secret import flag # Import the flag from a secret module

# Ensure the flag length matches the expected format
assert (len(flag) == len("CRYPTO25{}") + 36)

# Generate a random 192-bit key for AES encryption
key = get_random_bytes(24)

# Generate a random padding of length between 1 and 15 bytes
padding = get_random_bytes(randint(1, 15))

# Convert the flag to bytes
flag = flag.encode()

def encrypt() -> bytes:
    """
    Encrypts user-provided data concatenated with random padding and the flag using AES in ECB mode.
    Pads the payload to match the AES block size before encryption.
    """
    # Prompt the user for input data in hex format
    data = bytes.fromhex(input("> ").strip()) # Convert the input from hex to bytes

    # Concatenate the random padding, user-provided data, and the flag
    payload = padding + data + flag

    # Create an AES cipher in ECB mode
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    # Encrypt the padded payload and print the ciphertext in hex format
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())

def main():
    """
    Main function to display the menu and handle user commands.
    Allows the user to encrypt data or quit the program.
    """
    # Define the menu options
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        # Prompt the user for a command
        cmd = input(menu).strip()

        if cmd == "quit":   # Exit the program
            break
        elif cmd == "help": # Show the menu again
            continue
        elif cmd == "enc":  # Encrypt user-provided data
            encrypt()

if __name__ == '__main__':
    main() # Run the main function
