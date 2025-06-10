# Forge another JSON cookie

# ...it's more or less the same but with more errors to manage!
# nc 130.192.5.212 6551

# === Attack Overview ===
# - Attack Type: JSON-Block Splicing via ECB Token Forgery
# - Implementation Attack
# - Weakness: AES-ECB mode allows block splicing and manipulation
# - Brief Attack Description:
#     By carefully crafting the username so that the JSON structure aligns
#     sensitive fields into separate AES blocks, and then rearranging the
#     ciphertext blocks, an attacker can forge a token with "admin": true.

# === Attack Steps ===
#   1. Connect to the service and request a token for a carefully crafted username
#      such that, when serialized as JSON, the plaintext “{"username": <name>, "admin": false}”
#      aligns into 16-byte blocks in a controlled manner.
#   2. Decode the Base64-encoded token to obtain its raw AES-ECB ciphertext blocks.
#   3. Identify and reorder specific ciphertext blocks to forge a new token where
#      “"admin": true” appears in place of “"admin": false” without invalidating padding.
#   4. Base64-encode the forged ciphertext and submit it to the “flag” endpoint to retrieve the flag.

# === Flag ===
# CRYPTO25{d153d414-d83d-45f2-9f90-f6628c479331}

from pwn import *
from base64 import b64decode, b64encode
import json

context.log_level = 'info'

# Server configuration
HOST = '130.192.5.212'
PORT = 6551

BLOCK_SIZE = 16

def get_token(name, r):
    r.sendlineafter(b'name!\n> ', name)
    r.recvuntil(b'token: ')
    token = r.recvline().strip().decode()
    return b64decode(token)

def get_flag(forged_token, r):
    r.recvuntil(b'> ')  # Wait for menu prompt
    r.sendline(b'flag') # Request flag
    r.sendlineafter(b'token?\n> ', b64encode(forged_token))
    return r.recvall()

def main():
    r = remote(HOST, PORT)

    # Carefully crafted username to align JSON fields into specific AES blocks.
    # Each part is commented to explain its purpose in block alignment.
    name1 = (
        b'ab'            # 2 bytes: Start of username
        + b' ' * 15      # 15 spaces: Padding to fill the first block (total 17 so far)
        + b'"surname'    # 8 bytes: Start of a fake field to push "admin" into its own block
        + b' ' * 8       # 8 spaces: Padding to align the next field
        + b' ' * 15      # 15 spaces: More padding for block alignment
        + b'":'          # 2 bytes: End of fake field name and colon
        + b' ' * 14      # 14 spaces: Padding to align the value
        + b'true,'       # 5 bytes: The value "true," to be used for the "admin" field
        + b' ' * 11      # 11 spaces: Padding to fill the block
        + b'1234'        # 4 bytes: Extra to ensure proper block structure
    )
    # log.info("Crafted name: " + name1.decode())

    # Get encrypted token and split into blocks
    token1 = get_token(name1, r)
    blocks1 = [token1[i:i+BLOCK_SIZE] for i in range(0, len(token1), BLOCK_SIZE)]
    log.info("Received token blocks:")
    for i, block in enumerate(blocks1):
        log.info(f"Block {i}: {block.hex()}")

    # Forge new token by rearranging blocks
    # Block0: Header with username start
    # Block6: Continuation of username and "admin" field
    # Block5: "true" value
    # Block2: Extra field name ("surname")
    # Block4: Colon and spaces for extra field
    # Block7: "false" value for extra field (with padding)
    forged = blocks1[0] + blocks1[6] + blocks1[5] + blocks1[2] + blocks1[4] + blocks1[7]
    log.success("Forged token (Base64): " + b64encode(forged).decode())

    # Send forged token to get flag
    response = get_flag(forged, r)
    log.success(response.decode())

if __name__ == "__main__":
    main()
