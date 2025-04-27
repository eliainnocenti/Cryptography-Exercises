# Guess Mode One-Shot

## Challenge

In this challenge, the server encrypts data using either AES in ECB mode or CBC mode. The goal is to correctly guess the encryption mode based on the ciphertext provided by the server. If you guess the mode correctly for all challenges, you will receive the flag.

The `chall.py` file simulates the server's behavior. Here's a breakdown of its functionality:
- It randomly selects either ECB or CBC mode for each challenge.
- It generates a random one-time pad (OTP) and XORs it with the user-provided input before encryption.
- The user must analyze the ciphertext and guess the mode (ECB or CBC).
- If the user guesses incorrectly, the challenge ends.

Key points in `chall.py`:
- **ECB Mode**: Encrypts blocks independently, so identical plaintext blocks produce identical ciphertext blocks.
- **CBC Mode**: Uses an initialization vector (IV) and chains blocks, so identical plaintext blocks produce different ciphertext blocks.

## Main Logic

The main logic for solving this challenge is:
1. Understand how ECB and CBC modes work.
2. Use the server's behavior to distinguish between the two modes:
   - In ECB mode, identical plaintext blocks result in identical ciphertext blocks.
   - In CBC mode, the chaining mechanism ensures that ciphertext blocks differ, even for identical plaintext blocks.
3. Craft inputs that allow you to detect repeating patterns in the ciphertext.

## How to Solve It

To solve the challenge:
1. Send a carefully crafted input to the server.
2. Analyze the ciphertext to detect repeating blocks.
3. If repeating blocks are found, the mode is ECB; otherwise, it's CBC.
4. Repeat this process for all challenges.

### Crafting Input
The input is crafted by XORing the OTP with a block of zeros. This isolates the OTP, allowing the ciphertext to reveal patterns indicative of the encryption mode:
````python
def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

block = b'\x00' * 16
data_part1 = xor(otp1, block)
data_part2 = xor(otp2, block)
data = data_part1 + data_part2
````

### Detecting the Mode
The `detect_mode` function analyzes the ciphertext to determine if the mode is ECB or CBC:
````python
def detect_mode(ciphertext):
    block_size = 16 # AES block size
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    return "ECB" if len(blocks) != len(set(blocks)) else "CBC"
````

### Error Handling
The `solve.py` script includes robust error handling to manage unexpected server responses, such as empty OTPs or ciphertexts. This ensures the script can handle edge cases gracefully.

### Progress Tracking
The script uses `tqdm` to display a progress bar for the challenges:
````python
with tqdm(total=total_challenges, desc="Solving Challenges", unit="challenge") as pbar:
    ...
````

By following this structured approach, the script successfully solves the challenge and retrieves the flag.
