import time
from random import randint

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long

from secret import flag # Import the flag from a secret module
from flask import Flask, session, jsonify, request
from flask_session import Session

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = get_random_bytes(16).hex() # Generate a random secret key for Flask sessions
app.config['SESSION_TYPE'] = 'filesystem' # Configure session storage to use the filesystem
sess = Session()
sess.init_app(app) # Initialize Flask-Session with the app

def make_cipher():
    """
    Creates a new ChaCha20 cipher with a random key and nonce.
    Returns the nonce, key, and cipher object.
    """
    key = get_random_bytes(32)   # Generate a random 256-bit key
    nonce = get_random_bytes(12) # Generate a random 96-bit nonce
    cipher = ChaCha20.new(key=key, nonce=nonce) # Create a ChaCha20 cipher
    return nonce, key, cipher

def sanitize_field(field: str):
    """
    Sanitizes a field by removing or replacing unsafe characters.
    Ensures the field does not contain characters that could break the cookie format.
    """
    return field \
        .replace(" ", "_") \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")

def parse_cookie(cookie: str) -> dict:
    """
    Parses a cookie string into a dictionary.
    Sanitizes both keys and values to ensure safety.
    """
    parsed = {}
    for field in cookie.split("&"):   # Split the cookie into key-value pairs
        key, value = field.split("=") # Split each pair into key and value
        key = sanitize_field(key)     # Sanitize the key
        value = sanitize_field(value) # Sanitize the value
        parsed[key] = value # Add the sanitized key-value pair to the dictionary
    return parsed

@app.route("/login", methods=["GET"])
def login():
    """
    Handles the login process by creating a cookie for the user.
    Encrypts the cookie using ChaCha20 and returns the nonce and encrypted cookie.
    """
    username = request.args.get("username") # Get the username from the request
    admin = int(request.args.get("admin"))  # Get the admin status from the request

    nonce, key, cipher = make_cipher() # Create a new cipher
    session['key'] = key               # Store the key in the session

    username = sanitize_field(username) # Sanitize the username

    # Set admin status to 0 unless explicitly set to 1
    if admin != 1:
        admin = 0
    else:
        # Set an admin expiration date in the past
        session['admin_expire_date'] = int(time.time()) - randint(10, 259) * 24 * 60 * 60

    # Set the cookie expiration date to 30 days in the future
    expire_date = int(time.time()) + 30 * 24 * 60 * 60
    cookie = f"username={username}&expires={expire_date}&admin={admin}" # Create the cookie string

    # Return the nonce and encrypted cookie as JSON
    return jsonify({
        "nonce": bytes_to_long(nonce),
        "cookie": bytes_to_long(cipher.encrypt(cookie.encode()))
    })

@app.route("/flag", methods=["GET"])
def get_flag():
    """
    Handles the process of verifying the user's cookie and granting the flag.
    Decrypts the cookie, parses it, and checks if the user is an admin with a valid expiration date.
    """
    nonce = int(request.args.get("nonce"))   # Get the nonce from the request
    cookie = int(request.args.get("cookie")) # Get the encrypted cookie from the request

    # Create a ChaCha20 cipher with the provided nonce and the session key
    cipher = ChaCha20.new(nonce=long_to_bytes(nonce), key=session['key'])

    try:
        # Decrypt and decode the cookie
        dec_cookie = cipher.decrypt(long_to_bytes(cookie)).decode()
        token = parse_cookie(dec_cookie) # Parse the decrypted cookie into a dictionary

        # Check if the user is an admin
        if int(token["admin"]) != 1:
            return "You are not an admin!"

        # Check if the admin expiration date is within the valid range
        if 290 * 24 * 60 * 60 < abs(int(token["expires"]) - session['admin_expire_date']) < 300 * 24 * 60 * 60:
            return f"OK! Your flag: {flag}" # Grant access and return the flag
        else:
            return "You have expired!" # Deny access if the expiration date is invalid
    except:
        # Handle errors during decryption or parsing
        return "Something didn't work :C"
