from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from secret import flag
import json
import base64

# Generate a random 32-byte AES key
key = get_random_bytes(32)

def get_user_token(name):
    # Create a new AES cipher in ECB mode
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    # Construct a JSON token with the username and admin status
    token = json.dumps({
        "username": name,
        "admin": False
    })
    # Encrypt the padded token and encode as base64
    enc_token = cipher.encrypt(pad(token.encode(), AES.block_size))
    return f"{base64.b64encode(enc_token).decode()}"

def check_user_token(token):
    # Decrypt and unpad the base64-encoded token
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    dec_token = unpad(cipher.decrypt(base64.b64decode(token)), AES.block_size)

    # Parse the JSON token
    user = json.loads(dec_token)

    # Check if the user is admin
    if user.get("admin", False) == True:
        return True
    else:
        return False

def get_flag():
    # Ask the user for their token and check admin status
    token = input("What is your token?\n> ").strip()
    if check_user_token(token):
        print("You are admin!")
        print(f"This is your flag!\n{flag}")
    else:
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)

if __name__ == "__main__":
    # Ask for username and generate a token
    name = input("Hi, please tell me your name!\n> ").strip()
    token = get_user_token(name)
    print("This is your token: " + token)

    # Simple menu for user interaction
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "flag":
            get_flag()
