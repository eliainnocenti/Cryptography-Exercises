import json
import base64

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

from secret import flag # Import the flag from a secret module

# Generate a random 256-bit key for ChaCha20 encryption
key = get_random_bytes(32)

def make_cipher():
    """
    Creates a new ChaCha20 cipher with a random nonce.
    Returns the nonce and the cipher object.
    """
    nonce = get_random_bytes(12) # Generate a random 96-bit nonce
    cipher = ChaCha20.new(key=key, nonce=nonce) # Create a ChaCha20 cipher
    return nonce, cipher

def get_user_token(name):
    """
    Generates an encrypted token for the given username.
    The token is a JSON object containing the username, encrypted with ChaCha20.
    """
    nonce, cipher = make_cipher() # Create a new cipher
    token = json.dumps({
        "username": name # Create a JSON object with the username
    })
    print(token) # Print the plaintext token for debugging
    enc_token = cipher.encrypt(token.encode()) # Encrypt the token
    
    # Return the nonce and encrypted token, base64-encoded and concatenated
    return f"{base64.b64encode(nonce).decode()}.{base64.b64encode(enc_token).decode()}"

def check_user_token(token):
    """
    Decrypts and verifies the given token.
    Returns True if the token contains "admin": True, otherwise False.
    """
    nonce, token = token.split(".") # Split the token into nonce and ciphertext
    nonce = base64.b64decode(nonce) # Decode the nonce from base64
    cipher = ChaCha20.new(key=key, nonce=nonce) # Create a cipher with the same nonce
    dec_token = cipher.decrypt(base64.b64decode(token)) # Decrypt the token

    user = json.loads(dec_token) # Parse the decrypted token as JSON

    # Check if the user is an admin
    if user.get("admin", False) == True:
        return True
    else:
        return False

def get_flag():
    """
    Prompts the user for a token and checks if they are an admin.
    If they are, prints the flag; otherwise, exits with an error.
    """
    token = input("What is your token?\n> ").strip() # Get the token from the user
    if check_user_token(token): # Check if the token is valid and the user is an admin
        print("You are admin!") # Inform the user they are an admin
        print(f"This is your flag!\n{flag}") # Print the flag
    else:
        print("HEY! WHAT ARE YOU DOING!?") # Error message for invalid tokens
        exit(1) # Exit the program

if __name__ == "__main__":
    # Prompt the user for their name and generate a token
    name = input("Hi, please tell me your name!\n> ").strip()
    token = get_user_token(name) # Generate a token for the user
    print("This is your token: " + token) # Print the token

    # Display the menu and handle user commands
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip() # Get the user's command

        if cmd == "quit":   # Exit the program
            break
        elif cmd == "help": # Show the menu again
            continue
        elif cmd == "flag": # Attempt to get the flag
            get_flag()
