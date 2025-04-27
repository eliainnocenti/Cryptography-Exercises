from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long

from secret import flag # Import the flag from a secret module

# Generate a random 256-bit key for AES encryption
key = get_random_bytes(32)

def sanitize_field(field: str):
    """
    Sanitizes a field by removing or replacing unsafe characters.
    Ensures the field does not contain characters that could break the cookie format.
    """
    return field \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")

def parse_cookie(cookie: str) -> dict:
    """
    Parses a cookie string into a dictionary.
    Sanitizes both keys and values to ensure safety.
    """
    parsed = {}
    for field in cookie.split("&"):           # Split the cookie into key-value pairs
        key, value = field.strip().split("=") # Split each pair into key and value
        key = sanitize_field(key.strip())     # Sanitize the key
        value = sanitize_field(value.strip()) # Sanitize the value
        parsed[key] = value                   # Add the sanitized key-value pair to the dictionary

    return parsed

def login():
    """
    Handles the login process by creating a cookie for the user.
    Encrypts the cookie using AES in ECB mode and prints it as a long integer.
    """
    username = input("Username: ")      # Prompt the user for a username
    username = sanitize_field(username) # Sanitize the username

    cipher = AES.new(key, AES.MODE_ECB) # Create an AES cipher in ECB mode

    # Create a cookie with the username and admin status set to false
    cookie = f"username={username}&admin=false"

    # Encrypt the padded cookie and print it as a long integer
    print(bytes_to_long(cipher.encrypt(pad(cookie.encode(), AES.block_size))))

def get_flag():
    """
    Handles the process of verifying the user's cookie and granting the flag.
    Decrypts the cookie, parses it, and checks if the user is an admin.
    """
    cookie = int(input("Cookie: ")) # Prompt the user for their encrypted cookie

    cipher = AES.new(key=key, mode=AES.MODE_ECB) # Create an AES cipher in ECB mode

    try:
        # Decrypt and unpad the cookie, then decode it to a string
        dec_cookie = unpad(cipher.decrypt(
            long_to_bytes(cookie)), AES.block_size).decode()
        token = parse_cookie(dec_cookie) # Parse the decrypted cookie into a dictionary

        # Check if the user is an admin
        if token["admin"] != 'true':
            print("You are not an admin!") # Deny access if the user is not an admin
            return

        # Grant access and print the flag if the user is an admin
        print(f"OK! Your flag: {flag}")
    except:
        # Handle errors during decryption or parsing
        print("Something didn't work :C")

if __name__ == "__main__":
    login()  # Perform the login process

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
