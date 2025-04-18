# guess mode one-shot

# Read the code. If you really understood it, you can correctly guess the mode. 
# If you do it with a probability higher than 2^128 you'll get the flag.
# nc 130.192.5.212 6531

from pwn import *
from tqdm import tqdm

# Remote server details
HOST = "130.192.5.212"
PORT = 6531

DEBUG = False  # Set to False to disable debug outputs

def debug_output(func):
    """
    Decorator to control debug outputs based on the DEBUG variable.
    """
    def wrapper(*args, **kwargs):
        if DEBUG:
            return func(*args, **kwargs)
    return wrapper

# Wrap tqdm.write with the debug_output decorator
tqdm_write_debug = debug_output(tqdm.write)

def detect_mode(ciphertext):
    """
    Detects if the encryption mode is ECB or CBC based on repeating blocks.
    ECB produces identical ciphertext blocks for identical plaintext blocks,
    while CBC does not due to the use of an IV.
    """
    if not ciphertext:
        raise ValueError("Ciphertext is empty. Cannot detect encryption mode.")
    block_size = 16 # AES block size

    # Split ciphertext into blocks of block_size
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]

    # If there are duplicate blocks, it's ECB; otherwise, it's CBC
    return "ECB" if len(blocks) != len(set(blocks)) else "CBC"

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
    Main function to interact with the server, send crafted inputs,
    and determine the encryption mode.
    Includes error handling for unexpected server responses.
    """
    total_challenges = 128 # Total number of challenges
    print("Starting the challenge-solving process...\n")

    try:
        conn = remote(HOST, PORT) # Establish a connection to the server
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        return

    # Use tqdm to display a progress bar
    with tqdm(total=total_challenges, desc="Solving Challenges", unit="challenge") as pbar:
        for i in range(total_challenges):
            try:
                # Wait for the challenge number prompt from the server
                tqdm_write_debug(f"\nChallenge #{i + 1}/{total_challenges}")
                conn.recvuntil(f'Challenge #{i}\n'.encode())

                # Read the OTP line
                otp_line = conn.recvline().decode().strip()
                if not otp_line:
                    raise ValueError("Received an empty OTP line from the server.")

                otp_hex = otp_line.split(': ')[1]
                otp = bytes.fromhex(otp_hex)
                tqdm_write_debug(f"Parsed OTP: {otp_hex}")

                # Split the OTP into two 16-byte blocks
                otp1, otp2 = otp[:16], otp[16:]

                # Create a 16-byte block of zeros
                block = b'\x00' * 16

                # XOR the OTP blocks with the zero block to compute data parts
                data_part1 = xor(otp1, block)
                data_part2 = xor(otp2, block)
                data = data_part1 + data_part2

                # Send the computed data to the server
                conn.sendlineafter(b'Input: ', data.hex().encode())
                tqdm_write_debug(f"Sending crafted input: {data.hex()}")
                
                # Receive the ciphertext from the server
                output_line = conn.recvline().decode().strip()
                if not output_line:
                    raise ValueError("Received an empty ciphertext line from the server.")

                cipher_hex = output_line.split(': ')[1]
                cipher = bytes.fromhex(cipher_hex)
                tqdm_write_debug(f"Received ciphertext: {cipher.hex()}")
                
                # Split the ciphertext into two 16-byte blocks
                cipher1, cipher2 = cipher[:16], cipher[16:]
                
                # Determine the encryption mode based on the ciphertext blocks
                mode = 'ECB' if cipher1 == cipher2 else 'CBC'
                tqdm_write_debug(f"Detected mode: {mode}")
                
                # Send the guessed mode (ECB or CBC) to the server
                conn.sendlineafter(b'(ECB, CBC)\n', mode.encode())
                
                # Check the server's response to see if the guess was correct
                resp = conn.recvline().decode().strip()
                if not resp:
                    raise ValueError("Received an empty response from the server.")
                tqdm_write_debug(f"Server response: {resp}")
                
                if 'OK' not in resp:
                    tqdm_write_debug(f"Failed at challenge {i + 1}")
                    break
                
                # Update the progress bar
                pbar.update(1)

            except Exception as e:
                tqdm_write_debug(f"Error during challenge {i + 1}: {e}")
                break

    tqdm_write_debug("\n")

    try:
        # Receive the final response from the server
        final_response = conn.recvall(timeout=2).decode()
        if not final_response:
            raise ValueError("Received an empty final response from the server.")
        
        # Check for the flag in the final response
        if "flag" in final_response.lower():
            tqdm.write("\nFlag received!")
            tqdm.write(final_response)
        else:
            tqdm.write("No flag found in the final response.")
    except Exception as e:
        print(f"Error while receiving the final response: {e}")

    # Close the connection
    conn.close()

    print("Challenge-solving process completed.")

if __name__ == "__main__":
    main()
