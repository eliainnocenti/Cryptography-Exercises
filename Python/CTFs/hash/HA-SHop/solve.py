# HA-SHop

# Here at HA-SHop, we accept only coupons as payment. Do you have one to get the flag?
# nc 130.192.5.212 6630

"""
Steps:
1. Connect to remote service with pwntools' remote()
2. Request a coupon/MAC for a controlled username
3. Perform SHA-256 length-extension attack (hashpumpy) to increase value
4. Send forged coupon/MAC to purchase and retrieve the flag
"""

from pwn import remote, context
from hashpumpy import hashpump

# Server configuration
HOST = '130.192.5.212'
PORT = 6630

# We want the 'value' field > 100, so append &value=101
APPEND = b"&value=101"
# Secret key length from chall.py
SECRET_LEN = 16

# Set pwntools context
context.log_level = 'info' # change to 'debug' for verbose output

def get_coupon_and_mac(r, username: str = "attacker") -> tuple[bytes, str]:
    """
    Interact with the menu to fetch a valid coupon and its MAC.
    Returns raw coupon bytes and MAC hex string.
    """
    # Navigate menu to option 1
    r.recvuntil(b"Choose an option")
    r.sendline(b"1")

    # Prompt for username
    r.recvuntil(b"Enter your name:")
    r.sendline(username.encode())

    # Read 'Coupon: <hex>' line
    r.recvuntil(b"Coupon:")
    coupon_line = r.recvline().strip()
    coupon_hex = coupon_line.split()[0]

    # Read 'MAC: <hex>' line
    r.recvuntil(b"MAC:")
    mac_line = r.recvline().strip()
    mac_hex = mac_line.split()[0].decode()

    return bytes.fromhex(coupon_hex.decode()), mac_hex

def forge_coupon(coupon: bytes, mac_hex: str) -> tuple[bytes, str]:
    """
    Use hashpumpy to perform a length-extension attack on SHA-256 MAC.
    Returns hex-encoded forged coupon and new MAC.
    """
    # hashpump signature: (old_hash, original_data, data_to_append, key_length)
    new_hash, new_msg = hashpump(
        mac_hex,
        coupon,
        APPEND,
        SECRET_LEN
    )
    # new_msg is bytes of coupon+padding+APPEND, new_hash is hex digest
    return new_msg.hex().encode(), new_hash

def buy_with_forged(r, coupon_hex: bytes, mac_hex: str) -> None:
    """
    Send the forged coupon/MAC to purchase and print the result.
    """
    # Navigate menu to option 2
    r.recvuntil(b"Choose an option")
    r.sendline(b"2")

    # Send forged coupon
    r.recvuntil(b"Enter your coupon:")
    r.sendline(coupon_hex)

    # Send forged MAC
    r.recvuntil(b"Enter your MAC:")
    r.sendline(mac_hex.encode())

    # Print service response
    print(r.recvrepeat(timeout=2).decode(errors='ignore'))

def main():
    # Connect to the remote service
    r = remote(HOST, PORT)

    # Obtain a valid coupon and its MAC
    coupon, mac_hex = get_coupon_and_mac(r)
    print(f"[+] Original coupon:   {coupon}")
    print(f"[+] Original MAC:      {mac_hex}")

    # Forge a new coupon with elevated value
    forged_coupon, forged_mac = forge_coupon(coupon, mac_hex)
    print(f"[+] Forged coupon hex: {forged_coupon}")
    print(f"[+] Forged MAC:        {forged_mac}")

    # Use the forged coupon to retrieve the flag
    buy_with_forged(r, forged_coupon, forged_mac)

    r.close()

if __name__ == '__main__':
    main()
