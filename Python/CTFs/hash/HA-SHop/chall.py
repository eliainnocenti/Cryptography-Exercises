import hashlib                          # Import hashlib for SHA256 hashing
import os                               # Import os for generating random bytes
import re                               # Import re for regular expressions (input sanitization)
from binascii import unhexlify, hexlify # Import functions for hex encoding/decoding
from secret import flag                 # Import the secret flag from another file

SECRET = os.urandom(16) # Generate a random 16-byte secret key for MAC

def mac(message: bytes) -> str:
    # Compute the SHA256 MAC of the message using the secret key
    return hashlib.sha256(SECRET + message).hexdigest()

def get_coupon(username: str) -> tuple[str, str]:
    # Sanitize username to allow only alphanumeric characters and underscores
    sanitized_username = re.sub(r"[^\w]", "", username)
    coupon = f"username={sanitized_username}&value=10".encode() # Create coupon with username and value=10
    return hexlify(coupon).decode(), mac(coupon)                # Return hex-encoded coupon and its MAC

def buy(coupon: str, mac_hex: str) -> str:
    coupon = unhexlify(coupon) # Decode the hex-encoded coupon
    if mac(coupon) != mac_hex: # Verify the MAC
        return "Invalid MAC!"

    try:
        # Parse the coupon fields into a dictionary
        fields = dict(kv.split(b"=", 1)
                      for kv in coupon.split(b"&") if b"=" in kv)
        if fields.get(b"username") is None or fields.get(b"value") is None:
            return "Missing required fields."

        # Check if the value is greater than 100 to allow purchase
        if int(fields[b"value"]) > 100:
            return f"Purchase successful! Flag: {flag}"
        else:
            return "Insufficient balance!"
    except Exception as e:
        return f"Error: {e}"

def run_cli():
    print("=== Welcome to HA-SHop ===")
    while True:
        print("\nMenu:")
        print("1. Get a coupon")
        print("2. Buy")
        print("3. Exit")
        choice = input("Choose an option (1-3): ").strip()

        if choice == "1":
            username = input("Enter your name: ").strip()
            msg, tag = get_coupon(username)
            print(f"\nCoupon: {msg}")
            print(f"MAC:     {tag}")

        elif choice == "2":
            msg = input("Enter your coupon: ").strip()
            tag = input("Enter your MAC: ").strip()
            print(f"\nResult: {buy(msg, tag)}")

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    run_cli()
