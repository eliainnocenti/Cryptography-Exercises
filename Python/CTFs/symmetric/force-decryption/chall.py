from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from secret import flag # Import the flag from a secret module

# Generate a random 128-bit key for AES encryption
key = get_random_bytes(16)

# Define a specific value that cannot be encrypted or used as an IV
leak = b"mynamesuperadmin"

def make_cipher():
    """
    Creates a new AES cipher in CBC mode with a random IV.
    Returns the IV and the cipher object.
    """
    IV = get_random_bytes(16) # Generate a random 128-bit IV
    cipher = AES.new(key, AES.MODE_CBC, IV=IV) # Create an AES cipher in CBC mode
    return IV, cipher

def encrypt():
    """
    Prompts the user for input, encrypts it using AES-CBC, and prints the IV and ciphertext.
    Enforces restrictions on the input length and specific forbidden values.
    """
    string = input("What do you want to encrypt?\n> ") # Get input from the user
    string = bytes.fromhex(string) # Convert the input from hex to bytes

    # Ensure the input is exactly 16 bytes
    if len(string) != 16:
        print("Sorry, you can encrypt only 16 bytes!")
        return

    # Prevent encryption of the forbidden value
    if leak == string:
        print("Sorry, you can't encrypt that!")
        return

    # Create a new cipher and encrypt the input
    IV, cipher = make_cipher()
    encrypted = cipher.encrypt(string)

    # Print the IV and ciphertext in hex format
    print(f"IV: {IV.hex()}\nEncrypted: {encrypted.hex()}\n")

def decrypt():
    """
    Prompts the user for ciphertext and IV, decrypts the ciphertext using AES-CBC,
    and checks if the decrypted value matches the forbidden value.
    """
    string = input("What do you want to decrypt?\n> ") # Get ciphertext from the user
    string = bytes.fromhex(string) # Convert the ciphertext from hex to bytes

    IV = input("Gimme the IV\n> ") # Get the IV from the user
    IV = bytes.fromhex(IV)         # Convert the IV from hex to bytes

    # Prevent the use of the forbidden value as the IV
    if IV == leak:
        print("Nice try...")
        return

    # Create a cipher with the provided IV and decrypt the ciphertext
    cipher = AES.new(key, AES.MODE_CBC, IV=IV)
    decrypted = cipher.decrypt(string)

    # Check if the decrypted value matches the forbidden value
    if leak == decrypted:
        print(f"Good job. Your flag: {flag}")
    else:
        print(f"Mh, a normal day.\nDecrypted: {decrypted.hex()}")

if __name__ == '__main__':
    # Display the menu and handle user commands
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "dec - decrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip() # Get the user's command

        if cmd == "quit":   # Exit the program
            break
        elif cmd == "help": # Show the menu again
            continue
        elif cmd == "enc":  # Encrypt user input
            encrypt()
        elif cmd == "dec":  # Decrypt user input
            decrypt()
