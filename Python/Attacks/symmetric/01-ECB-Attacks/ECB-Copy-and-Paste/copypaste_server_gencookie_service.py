import sys
import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from mysecrets import ecb_oracle_key as key
from myconfig import HOST, PORT

# Function to create a user profile dictionary from an email
def profile_for(email):
    # Simulates a database access to get user data
    email = email.replace('=', '') # Remove invalid characters
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
    print(n) # Print the number of keys in the dictionary
    for key in dict.keys():
        s += key + "=" + str(dict[key])
        if i < (n - 1):
            s += "&"
            i += 1
    return s

# Function to encrypt a profile string using AES in ECB mode
def encrypt_profile(encoded_profile):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(), AES.block_size)  # Pad the plaintext to match the block size
    print("Padded plaintext: ", plaintext)  # Print the padded plaintext
    return cipher.encrypt(plaintext)

# Function to decrypt a ciphertext using AES in ECB mode
def decrypt_msg(ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)  # Unpad the decrypted plaintext

if __name__ == '__main__':
    # Create a TCP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    # Bind the socket to the specified host and port
    try:
        s.bind((HOST, PORT))
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

        # Receive the email from the client
        email = conn.recv(1024)
        # Generate and encrypt the cookie based on the email
        cookie = encrypt_profile(encode_profile(profile_for(email.decode())))

        # Print the plaintext representation of the cookie
        print("Cookie: " + encode_profile(profile_for(email.decode())))

        # Send the encrypted cookie back to the client
        conn.send(cookie)
        conn.close()

    # Close the socket (this line is unreachable in the current implementation)
    s.close()
