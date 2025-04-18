# forge a cookie

# Read and understand the code. You'll easily find a way to forge the target cookie.
# nc 130.192.5.212 6521

import base64
import json
import socket

# Remote server details
HOST = "130.192.5.212"
PORT = 6521

def xor(a, b):
    """
    XOR two byte strings of equal length.
    Raises an error if the lengths of the inputs do not match.
    """
    if len(a) != len(b):
        raise ValueError("Inputs to XOR must have the same length.")
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    """
    Main function to forge a cookie and retrieve the flag from the server.
    Includes error handling for unexpected server responses.
    """
    print("Starting the cookie-forging process...\n")

    # Craft the JSON we want to forge
    forged_data = {"username": "admin", "admin": True}
    forged_json = json.dumps(forged_data)
    forged_plaintext = forged_json.encode()

    # Choose a known username length so that the keystream is long enough
    known_username = "a" * len(forged_plaintext)

    try:
        # Connect to the remote service
        s = socket.create_connection((HOST, PORT))
        print("Connected to the server.")
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        return

    def recv_until(delim):
        """
        Receive data from the server until the specified delimiter is encountered.
        """
        data = b""
        while not data.endswith(delim):
            chunk = s.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    try:
        # Step 1: Send our known username to get a token encrypted under a predictable plaintext
        recv_until(b"> ")
        s.sendall((known_username + "\n").encode())
        print("Sent known username to the server.")

        # Step 2: Receive the token (base64(nonce).base64(ciphertext))
        resp = recv_until(b"> ")  # Wait for next prompt
        token_line = [line for line in resp.decode().split("\n") if "This is your token:" in line][0]
        token = token_line.split(": ")[1].strip()
        print(f"Received token: {token}")

        # Step 3: Decode nonce and ciphertext
        nonce_b64, ct_b64 = token.split('.')
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ct_b64)

        # Step 4: Recover the keystream from known plaintext
        known_plaintext = json.dumps({"username": known_username}).encode()
        keystream = xor(ciphertext, known_plaintext)
        print("Recovered keystream from known plaintext.")

        # Step 5: Encrypt our forged plaintext using the recovered keystream
        ks = keystream[:len(forged_plaintext)]
        forged_ciphertext = xor(forged_plaintext, ks)
        print("Encrypted forged plaintext using the recovered keystream.")

        # Step 6: Construct the forged token with the original nonce
        forged_token = f"{base64.b64encode(nonce).decode()}.{base64.b64encode(forged_ciphertext).decode()}"
        print(f"Forged token: {forged_token}")

        # Step 7: Send the command to get the flag, then send our forged token
        s.sendall(b"flag\n")
        recv_until(b"> ")
        s.sendall((forged_token + "\n").encode())
        print("Sent forged token to the server.")

        # Step 8: Print server response (should contain the flag)
        result = s.recv(4096)
        print("\n=== Server Response ===")
        print(result.decode())

    except Exception as e:
        print(f"Error during the cookie-forging process: {e}")
    finally:
        s.close()
        print("Connection to the server closed.")

if __name__ == "__main__":
    main()
