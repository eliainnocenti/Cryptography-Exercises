from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from random import randint
from secret import flag

# Ensure the flag is the expected length
assert (len(flag) == len("CRYPTO25{}") + 36)

# Generate a random 24-byte AES key
key = get_random_bytes(24)

# Randomly choose the length of the first padding (1 to 6 bytes)
padding1_len = randint(1, 6)
padding1 = get_random_bytes(padding1_len)
# The second padding fills up to 10 bytes total
padding2 = get_random_bytes(10 - padding1_len)
flag = flag.encode()

def encrypt() -> bytes:
    # Read user input as hex and convert to bytes
    data = bytes.fromhex(input("> ").strip())
    # Construct the payload: padding1 + user data + padding2 + flag
    payload = padding1 + data + padding2 + flag

    # Encrypt the padded payload using AES-ECB
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())

def main():
    # Simple menu for user interaction
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "enc":
            encrypt()

if __name__ == '__main__':
    main()
