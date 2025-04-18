import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from mysecrets import ecb_oracle_key, ecb_oracle_secret
from myconfig import HOST, PORT

# Create a socket for the server
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

# Main loop to handle incoming connections
# wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()  # Accept a new connection
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    input0 = conn.recv(1024).decode() # Receive the input from the client

    # Construct the plaintext message with the secret
    # ecb_oracle_secret is 16 bytes long, all printable strings
    message = """Here is the msg:{0} - and the sec:{1}""".format(input0, ecb_oracle_secret)
    message = pad(message.encode(), AES.block_size) # Pad the message to block size

    # Encrypt the message using AES in ECB mode
    cipher = AES.new(ecb_oracle_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(message)

    conn.send(ciphertext) # Send the ciphertext back to the client
    conn.close() # Close the connection

s.close() # Close the server socket
