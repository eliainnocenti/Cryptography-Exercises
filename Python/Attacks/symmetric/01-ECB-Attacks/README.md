# ECB (Electronic Codebook) Attack Exercises

This directory contains Python scripts demonstrating various attacks against the ECB encryption mode. ECB is fundamentally flawed because it encrypts identical plaintext blocks to identical ciphertext blocks, making it vulnerable to multiple attack vectors.

## Overview

ECB mode is the simplest block cipher mode of operation but also the most vulnerable. Each plaintext block is encrypted independently using the same key, which creates patterns in the ciphertext that can be exploited by attackers.

### Key Vulnerabilities of ECB Mode:
- **Deterministic encryption**: Identical plaintext blocks always produce identical ciphertext blocks
- **No diffusion**: Changes in one block don't affect other blocks
- **Pattern preservation**: Patterns in plaintext are preserved in ciphertext
- **Block manipulation**: Individual blocks can be copied, pasted, or rearranged

## Attack Scenarios

### 1. [ECB-ACP](ECB-ACP/) - Adaptive Chosen-Plaintext Attack

This directory demonstrates how to discover a secret string using an Adaptive Chosen-Plaintext Attack against an ECB encryption oracle.

#### Files:
- **[`ACP_attack_server.py`](ECB-ACP/ACP_attack_server.py)**: Server that encrypts messages containing a secret string using ECB mode
- **[`ACP_attack_client.py`](ECB-ACP/ACP_attack_client.py)**: Client that discovers the secret through systematic input manipulation
- **[`ACP_decryptionattack_video.py`](ECB-ACP/ACP_decryptionattack_video.py)**: Educational step-by-step implementation showing the attack methodology

#### Attack Strategy:
1. Control input to align secret characters at block boundaries
2. Compare ciphertext blocks to identify when guesses are correct
3. Build the secret character by character through systematic brute-force

### 2. [ECB-Copy-and-Paste](ECB-Copy-and-Paste/) - Block Manipulation Attack

This directory demonstrates how to forge authentication cookies by copying and pasting ciphertext blocks between different encrypted messages.

#### Files:
- **[`copypaste_attack.py`](ECB-Copy-and-Paste/copypaste_attack.py)**: Client that forges admin cookies by combining ciphertext blocks
- **[`copypaste_server_gencookie_service.py`](ECB-Copy-and-Paste/copypaste_server_gencookie_service.py)**: Server that generates encrypted user profile cookies
- **[`copypaste_testcookie_service.py`](ECB-Copy-and-Paste/copypaste_testcookie_service.py)**: Server that authenticates users based on encrypted cookies

#### Attack Strategy:
1. Generate legitimate cookies with controlled block alignment
2. Craft inputs to place "admin" in a separate block
3. Combine blocks from different cookies to create forged admin cookies
4. Use forged cookies to gain unauthorized admin access

### 3. [ECB-vs-CBC](ECB-vs-CBC/) - Mode Detection Attack

This directory demonstrates how to detect whether a server is using ECB or CBC mode by analyzing ciphertext patterns.

#### Files:
- **[`client.py`](ECB-vs-CBC/client.py)**: Client that detects encryption mode through pattern analysis
- **[`server.py`](ECB-vs-CBC/server.py)**: Server that randomly selects ECB or CBC mode for each connection

#### Attack Strategy:
1. Send crafted input with identical plaintext blocks
2. Analyze resulting ciphertext for patterns
3. Identical ciphertext blocks indicate ECB mode
4. Different ciphertext blocks indicate CBC mode

## Common Configuration Files

Each attack scenario uses common configuration files:

- **`myconfig.py`**: Server connection settings (HOST, PORT, etc.)
- **`mysecrets.py`**: Cryptographic keys and secrets used by servers

## Running the Exercises

### Prerequisites:
```bash
pip install pycryptodome pwn
```

### Basic Usage:
1. Start the appropriate server script
2. Run the corresponding client/attack script
3. Observe the attack results and analysis

### Example - Running the ACP Attack:
```bash
# Terminal 1: Start the server
python3 ECB-ACP/ACP_attack_server.py

# Terminal 2: Run the attack
python3 ECB-ACP/ACP_attack_client.py
```

## Detailed Attack Explanations

### ECB Mode Detection Attack

#### How the Attack Works:
1. **Start the Server**: Run `ECB-vs-CBC/server.py` to start the encryption server
2. **Run the Client**: Execute `ECB-vs-CBC/client.py` to connect and test the server
3. **Analyze the Ciphertext**: The client sends identical plaintext blocks and analyzes the response

#### Key Observations:
- **ECB Mode**: Identical plaintext blocks produce identical ciphertext blocks
- **CBC Mode**: Each ciphertext block depends on the previous block, introducing randomness

#### Example Output:
```
Sending: b'AAAAAAAAAAAAAAAAAAAAAAAA'
<hexadecimal ciphertext>
Selected mode is ECB
```

### ECB Copy & Paste Attack

#### How the Attack Works:
1. **Start Cookie Generation Server**: Run `ECB-Copy-and-Paste/copypaste_server_gencookie_service.py`
2. **Start Test Cookie Service**: Run `ECB-Copy-and-Paste/copypaste_testcookie_service.py`
3. **Run the Attack**: Execute `ECB-Copy-and-Paste/copypaste_attack.py`

#### Attack Steps:
- Craft a plaintext block containing "admin" padded to the block size
- Use the server to encrypt this block
- Replace the "role=user" block in a valid cookie with the "admin" block

#### Example Output:
```
Cookie: email=aaaaaaa@b.com&UID=10&role=user
Forged Cookie: email=aaaaaaa@b.com&UID=10&role=admin
You are an admin!
```

### ECB ACP (Adaptive Chosen Plaintext) Attack

#### How the Attack Works:
1. **Start the Server**: Run `ECB-ACP/ACP_attack_server.py`
2. **Run the Attack**: Execute `ECB-ACP/ACP_attack_client.py`

#### Attack Steps:
- Align the secret at the end of a block using padding
- Guess each character of the secret by comparing ciphertext blocks
- Repeat until the entire secret is discovered

#### Example Output:
```
Sending:  - and the sec:A
Found new character = A
Sending:  - and the sec:AB
Found new character = B
...
Secret discovered = ABCDEFGHIJKLMNOP
```

## Defense Against ECB Attacks

### Recommended Alternatives:
1. **CBC Mode**: Use with random IVs for each encryption
2. **CTR Mode**: Provides stream cipher-like properties
3. **GCM Mode**: Provides both confidentiality and authenticity

### Implementation Example:
```python
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# SECURE: Using CBC mode with random IV
def secure_encrypt(plaintext, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext

# INSECURE: Using ECB mode
def insecure_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)  # DON'T DO THIS!
    return cipher.encrypt(pad(plaintext, AES.block_size))
```
