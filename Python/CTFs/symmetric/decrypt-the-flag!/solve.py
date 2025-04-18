# decrypt the flag!

# As I don't have enough fantasy, I'm just reusing the same text as other challenges... 
# ...read the challenge code and find the flag!
# nc 130.192.5.212 6561

from pwn import remote

# Remote server details
HOST = "130.192.5.212"
PORT = 6561

DEBUG = False    # Set to True for verbose output
MAX_SEED = 1000  # Maximum seed value to try during brute-forcing

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings of the same length.
    Returns the result as a new byte string.
    """
    return bytes(x ^ y for x, y in zip(a, b))

def connect(seed: int):
    """
    Connect to the remote challenge server and initialize it with a seed.
    Returns a pwnlib connection object after setup.
    """
    try:
        # Establish a connection to the server
        conn = remote(HOST, PORT, level='error' if not DEBUG else 'debug')
        conn.recvuntil(b"> ")             # Wait for the server prompt
        conn.sendline(str(seed).encode()) # Send the seed to initialize the server
        return conn
    except Exception as e:
        print(f"[!] Connection failed for seed {seed}: {e}")
        return None

def read_encrypted_flag(conn):
    """
    Read the encrypted flag from the server after seeding.
    Returns the encrypted flag as bytes.
    """
    try:
        conn.recvuntil(b"secret!\n")                # Wait for the server to send the encrypted flag
        flag_hex = conn.recvline().strip().decode() # Read the flag in hex format
        return bytes.fromhex(flag_hex)              # Convert the hex string to bytes
    except Exception as e:
        print(f"[!] Error reading encrypted flag: {e}")
        return None

def send_known_plaintext(conn, length: int, char: bytes = b"A"):
    """
    Send a known plaintext of a given length to the server.
    Returns the plaintext and the corresponding ciphertext received from the server.
    """
    try:
        conn.recvuntil(b"(y/n)") # Wait for the server to ask if we want to encrypt something
        conn.sendline(b"y")      # Respond with 'yes'

        conn.recvuntil(b"message? ") # Wait for the server to prompt for the message
        known = char * length        # Create a plaintext of the specified length
        conn.sendline(known)         # Send the plaintext to the server
        ctxt_hex = conn.recvline().strip().decode() # Read the ciphertext in hex format
        return known, bytes.fromhex(ctxt_hex)       # Return the plaintext and ciphertext as bytes
    except Exception as e:
        print(f"[!] Error sending known plaintext: {e}")
        return None, None

def recover_flag(seed: int):
    """
    Full logic to connect to the server, send the seed, retrieve the encrypted flag,
    send a known plaintext, derive the keystream, and recover the flag.
    """
    conn = connect(seed) # Connect to the server with the given seed
    if not conn:
        return None

    flag_ct = read_encrypted_flag(conn) # Read the encrypted flag
    if not flag_ct:
        conn.close()
        return None

    known, known_ct = send_known_plaintext(conn, len(flag_ct)) # Send a known plaintext
    if not known_ct:
        conn.close()
        return None

    conn.close()  # Close the connection

    # Derive the keystream by XORing the known plaintext and its ciphertext
    keystream = xor_bytes(known_ct, known)

    # Decrypt the flag by XORing the encrypted flag with the keystream
    flag_plain = xor_bytes(flag_ct, keystream)

    return flag_plain

def main():
    """
    Main function to brute-force the seed, recover the flag, and print it.
    """
    print("[*] Starting brute-force attack...\n")

    # Iterate through all possible seeds
    for seed in range(MAX_SEED):
        print(f"[.] Trying seed: {seed}", end="\r")

        # Attempt to recover the flag with the current seed
        flag_plain = recover_flag(seed)
        if not flag_plain:
            continue

        if DEBUG:
            print(f"[+] Flag plaintext for seed {seed}: {flag_plain}")

        try:
            # Attempt to decode the flag as a string
            decoded = flag_plain.decode()

            # Check if the decoded flag contains the expected keyword
            if "crypto25" in decoded.lower():
                print(f"\n\n[+] Flag found using seed {seed}:")
                print(decoded)
                return
        except UnicodeDecodeError:
            if DEBUG:
                print(f"[!] Could not decode flag for seed {seed}.")
            continue

    print("\n[-] Flag not found in the given seed range.")

if __name__ == "__main__":
    main()
