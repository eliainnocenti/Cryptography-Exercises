import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random.random import getrandbits

from mysecrets import ecb_oracle_key
from myconfig import HOST, PORT

# Constants to represent encryption modes
ECB_MODE = 0
CBC_MODE = 1

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
# wait to accept a connection - blocking call
while 1:
    conn, addr = s.accept()
    print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

    # Randomly select a mode of operation: ECB or CBC
    selected_mode = getrandbits(1)
    print("Selected mode = ", end='')
    if selected_mode == ECB_MODE:
        print("ECB")
    else:
        print("CBC")

    # Receive plaintext input from the client
    input0 = conn.recv(1024).decode()
    message = "This is what I received: " + input0 + " -- END OF MESSAGE"
    print("Plaintext: " + message)

    # Encrypt the plaintext using the selected mode
    if selected_mode == ECB_MODE:
        cipher = AES.new(ecb_oracle_key, AES.MODE_ECB)
    else:
        cipher = AES.new(ecb_oracle_key, AES.MODE_CBC)

    # Pad the message to match the block size and encrypt it
    message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(message)

    # Send the ciphertext back to the client
    conn.send(ciphertext)

    # Close the connection
    conn.close()

# Close the socket (this line is unreachable in the current implementation)
s.close()
