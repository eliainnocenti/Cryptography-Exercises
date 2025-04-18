import sys
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from mysecrets import ecb_oracle_key as key
from myconfig import HOST, PORT, DELTA_PORT

# Function to create a user profile dictionary from an email
def profile_for(email):
    email = email.replace('=', '')  # Remove invalid characters
    email = email.replace('&', '')

    dict = {}
    dict["email"] = email
    dict["UID"] = 10
    dict["role"] = "user"
    return dict

# Function to encode a profile dictionary into a string
def encode_profile(dict):
    """
    :type dict: dictionary
    """
    s = ""
    i = 0
    n = len(dict.keys())
    print(n)
    for key in dict.keys():
        s += key + "=" + str(dict[key])
        if i < (n - 1):
            s += "&"
            i += 1
    return s

# Function to encrypt a profile string using AES in ECB mode
def encrypt_profile(encoded_profile):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(), AES.block_size)
    print("Padded plaintext: ", plaintext)  # Print the padded plaintext
    return cipher.encrypt(plaintext)

# Function to decrypt a ciphertext using AES in ECB mode
def decrypt_msg(ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

if __name__ == '__main__':
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    # Bind the socket to the specified host and port
    try:
        s.bind((HOST, PORT + DELTA_PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    # Start listening for incoming connections
    s.listen(10)
    print('Socket now listening')

    # Main server loop to handle incoming connections
    while 1:
        conn, addr = s.accept()
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        # Receive the encrypted cookie from the client
        received_cookie = conn.recv(1024)
        cipher_dec = AES.new(key, AES.MODE_ECB)

        try:
            # Attempt to decrypt the received cookie
            decrypted = unpad(cipher_dec.decrypt(received_cookie), AES.block_size)
        except ValueError:
            print("Wrong padding")
            continue

        print("Decrypted cookie: " + str(decrypted))

        # Check if the decrypted cookie contains admin privileges
        if b'role=admin' in decrypted:
            print("You are an admin!")
            conn.send("You are an admin!".encode())
        else:
            # Extract and display user information
            i1 = decrypted.index(b'=')
            i2 = decrypted.index(b',')
            msg = "welcome" + decrypted[i1:i2].decode('utf-8')
            print("You are a normal user")
            print(msg)
            conn.send(msg.encode())

        conn.close()

    s.close()
