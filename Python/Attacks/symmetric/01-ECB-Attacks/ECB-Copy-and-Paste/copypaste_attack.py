import os
os.environ['PWNLIB_NOTERM'] = 'True' # Configuration patch to allow pwntools to be run inside of an IDE
os.environ['PWNLIB_SILENT'] = 'True'

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from copypaste_server_gencookie_service import profile_for, encode_profile
from myconfig import HOST, PORT, DELTA_PORT

if __name__ == '__main__':
    # Connect to the server that generates encrypted cookies
    server_gencookies = remote(HOST, PORT)
    email = b'aaaaaaa@b.com' # Email to send for cookie generation

    # Send the email to the server and receive the encrypted cookie
    server_gencookies.send(email)
    encrpyted_cookie = server_gencookies.recv(1024)
    print("Encrypted cookie:" + str(encrpyted_cookie))

    # Generate and encode the profile locally for comparison
    cookie_info = encode_profile(profile_for(email.decode()))
    print("Cookie info: " + str(cookie_info))
    print("First block of the encoded profile:  " + str(cookie_info[0:16]))  # First block of the encoded profile
    print("Second block of the encoded profile: " + str(cookie_info[16:32])) # Second block of the encoded profile

    # Craft a padded "admin" block to inject into the cookie
    padded_admin = b'A' * 10 + pad(b'admin', AES.block_size)
    cookie_info = encode_profile(profile_for(padded_admin.decode()))
    print("Padded admin block: " + str(cookie_info))
    print("First block of the crafted profile:  " + str(cookie_info[0:16]))           # First block of the crafted profile
    print("Second block of the crafted profile: " + str(cookie_info[16:32].encode())) # Second block of the crafted profile
    server_gencookies.close()

    # Send the crafted "admin" block to the server
    server_gencookies = remote(HOST, PORT)
    server_gencookies.send(padded_admin)
    encrpyted_cookie_2 = server_gencookies.recv(1024)
    server_gencookies.close()

    print("Encrypted cookie 2: " + str(encrpyted_cookie_2))

    # Combine blocks from the original and crafted cookies to create an admin cookie
    auth_cookie = encrpyted_cookie[0:32] + encrpyted_cookie_2[16:32]
    server_test = remote(HOST, PORT + DELTA_PORT)

    # Send the forged admin cookie to the test server
    server_test.send(auth_cookie)
    answer = server_test.recv(1024)

    # Print the server's response
    print(answer.decode())
