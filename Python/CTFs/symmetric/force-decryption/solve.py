# force decryption

# To get your flag, forge a payload that decrypts to a fixed value...
# nc 130.192.5.212 6523

import socket
import binascii

# Remote server details
HOST = '130.192.5.212'
PORT = 6523

# The value we want the server to decrypt to
leak = b"mynamesuperadmin"

def connect():
    """
    Establishes a connection to the remote server.
    Returns the connected socket object.
    """
    return socket.create_connection((HOST, PORT))

def recv_until(sock, delim):
    """
    Reads data from the socket until the specified delimiter is encountered.
    """
    data = b""
    while not data.endswith(delim):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data

def send_hex(sock, b):
    """
    Converts bytes to hex and sends them to the server, followed by a newline.
    """
    sock.sendall(binascii.hexlify(b) + b"\n")

def main():
    """
    Main function to forge a payload and retrieve the flag from the server.
    Includes error handling for unexpected server responses.
    """
    print("Starting the decryption-forging process...\n")

    try:
        s = connect()
        print("Connected to the server.")
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        return

    try:
        # Step 1: Get to the menu and send 'enc'
        recv_until(s, b"> ")
        s.sendall(b"enc\n")
        print("Sent 'enc' command to the server.")

        # Step 2: Encrypt 16 null bytes
        recv_until(s, b"> ")
        s.sendall(b"00" * 16 + b"\n")  # plaintext = 16 null bytes
        print("Sent 16 null bytes for encryption.")

        # Step 3: Read back the IV and ciphertext
        output = recv_until(s, b"> ").decode()
        lines = output.splitlines()
        iv_line = [line for line in lines if line.startswith("IV")][0]
        ct_line = [line for line in lines if line.startswith("Encrypted")][0]

        iv = bytes.fromhex(iv_line.split(": ")[1])
        ct = bytes.fromhex(ct_line.split(": ")[1])

        print(f"Original IV: {iv.hex()}")
        print(f"Ciphertext: {ct.hex()}")

        # Step 4: Forge the IV to produce the desired decrypted value
        # Since plaintext = 0s, we know: D_K(C) = IV
        # We want: decrypted = leak = D_K(C) ⊕ forged_IV
        # => forged_IV = IV ⊕ leak
        forged_iv = bytes(a ^ b for a, b in zip(iv, leak))
        print(f"Forged IV: {forged_iv.hex()}")

        # Step 5: Send decrypt command with original ciphertext and forged IV
        s.sendall(b"dec\n")
        recv_until(s, b"> ")
        send_hex(s, ct)
        recv_until(s, b"> ")
        send_hex(s, forged_iv)
        print("Sent forged IV and ciphertext to the server.")

        # Step 6: Print the server's response (should contain the flag)
        result = s.recv(4096)
        print("\n=== Server Response ===")
        print(result.decode())

    except Exception as e:
        print(f"Error during the decryption-forging process: {e}")
    finally:
        s.close()
        print("Connection to the server closed.")

if __name__ == "__main__":
    main()
