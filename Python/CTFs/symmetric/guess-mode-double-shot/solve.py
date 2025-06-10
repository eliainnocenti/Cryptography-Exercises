# guess-mode double-shot

# Guess the mode. Now you need to reason about how modes work. 
# Ask a second encryption to confirm your hypothesis...
# nc 130.192.5.212 6532

from pwn import remote
from tqdm import tqdm

# Remote server details
HOST = "130.192.5.212"
PORT = 6532

BLOCK_SIZE = 16

DEBUG = False  # Set to False to disable debug outputs

def debug_output(func):
    """
    Decorator to control debug outputs based on the DEBUG variable.
    """
    def wrapper(*args, **kwargs):
        if DEBUG:
            return func(*args, **kwargs)
    return wrapper

# Wrap tqdm.write with the debug_output decorator
tqdm_write_debug = debug_output(tqdm.write)

# We no longer detect ECB by repeated blocks (broken by OTP),
# but by checking whether two encryptions of identical input yield identical ciphertext.
def is_ecb(ct1: bytes, ct2: bytes) -> bool:
    """
    In ECB mode, two separate encrypt() calls on the same plaintext produce the same ciphertext.
    In CBC mode (stateful chaining), the second encrypt call continues the chain, so ciphertexts differ.
    """
    return ct1 == ct2

def detect_mode(conn) -> str:
    """
    Perform the two-shot encryption oracle:
    - Send identical 32-byte payload twice
    - Compare the two ciphertext outputs directly
    - If identical => ECB, else => CBC
    """
    payload = b'A' * (BLOCK_SIZE * 2)
    hex_payload = payload.hex().encode()

    # First encryption call
    conn.recvuntil(b"Input: ")
    conn.sendline(hex_payload)
    out1 = conn.recvline().decode()
    ct1 = bytes.fromhex(out1.split(':', 1)[1].strip())

    # Second encryption call
    conn.recvuntil(b"Input: ")
    conn.sendline(hex_payload)
    out2 = conn.recvline().decode()
    ct2 = bytes.fromhex(out2.split(':', 1)[1].strip())

    # In ECB, ct1 == ct2. In CBC, chaining makes them differ.
    return "ECB" if is_ecb(ct1, ct2) else "CBC"

def main():
    """
    Main function to interact with the server, send crafted inputs,
    and determine the encryption mode.
    Includes error handling for unexpected server responses.
    """
    print("Starting the challenge-solving process...\n")

    try:
        conn = remote(HOST, PORT)  # Establish a connection to the server
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        return

    total_challenges = 128  # Total number of challenges
    with tqdm(total=total_challenges, desc="Solving Challenges", unit="challenge") as pbar:
        for i in range(total_challenges):
            try:
                # Read "Challenge #i"
                line = conn.recvline()
                if not line or b"Challenge" not in line:
                    tqdm_write_debug(f"[-] Unexpected response: {line}")
                    return
                tqdm_write_debug(line.decode().strip())

                # Detect mode by interacting twice
                mode_guess = detect_mode(conn)
                tqdm_write_debug(f"[+] Guessed: {mode_guess}")

                # Read the rest of the prompt up through the newline
                conn.recvuntil(b"(ECB, CBC)\n")
                # Send our guess
                conn.sendline(mode_guess.encode())

                # Read verdict: "OK, next" or "Wrong, sorry"
                verdict = conn.recvline().decode().strip()
                tqdm_write_debug(f"[=] Verdict: {verdict}")
                if verdict.startswith("Wrong"):
                    tqdm_write_debug(f"[-] Failed at round {i}")
                    conn.close()
                    return

                # Update the progress bar
                pbar.update(1)

            except Exception as e:
                tqdm.write(f"Error during challenge {i + 1}: {e}")
                break

    try:
        # After 128 correct guesses, read the flag
        flag_line = conn.recvline().decode().strip()
        tqdm.write("[!] " + flag_line)
    except Exception as e:
        tqdm.write(f"Error while receiving the flag: {e}")
    finally:
        conn.close()
        tqdm.write("Connection to the server closed.")

if __name__ == "__main__":
    main()
