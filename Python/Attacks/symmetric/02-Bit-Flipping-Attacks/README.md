# Bit-Flipping Attack Exercises

This directory contains Python scripts demonstrating bit-flipping attacks against CBC mode encryption. These attacks exploit the malleability of CBC mode to modify specific bits in the decrypted plaintext by flipping corresponding bits in the ciphertext.

## Overview

Bit-flipping attacks are a class of cryptographic attacks that exploit the mathematical properties of certain encryption modes, particularly CBC (Cipher Block Chaining) mode. The attack works because of how CBC mode decryption operates:

**CBC Decryption Formula:** `P[i] = Decrypt(C[i]) XOR C[i-1]`

This means that flipping a bit in ciphertext block `C[i-1]` will flip the corresponding bit in plaintext block `P[i]`.

## Vulnerability Details

### Why CBC Mode is Vulnerable:
- **Bit malleability**: Changes to ciphertext bits predictably affect plaintext bits
- **Lack of authentication**: CBC mode provides no integrity protection
- **Precise targeting**: Attackers can modify specific characters without affecting others

### Attack Requirements:
1. Access to modify ciphertext (man-in-the-middle or stored data)
2. Knowledge of the plaintext structure
3. Ability to observe the effects of modifications

## Attack Scenarios

### Core Attack Files

#### [`bf_server_cbc.py`](bf_server_cbc.py)
**CBC Bit-Flipping Attack Vulnerable Server**

This server demonstrates a vulnerable authentication system that uses CBC mode encryption for user cookies.

**Vulnerability:**
- Generates cookies with format: `username=<user>,admin=0`
- Uses CBC mode without integrity protection
- Grants admin access based on `admin=1` in decrypted cookie

**Process:**
1. Client sends username
2. Server generates encrypted cookie with `admin=0`
3. Server sends encrypted cookie back
4. Client can modify cookie and send it back
5. Server decrypts and checks for admin privileges

**Educational Value:**
- Shows how CBC mode can be exploited for privilege escalation
- Demonstrates the importance of authenticated encryption
- Illustrates why encryption alone is insufficient for authentication

#### [`bf_client.py`](bf_client.py)
**CBC Bit-Flipping Attack Client**

This client demonstrates how to exploit the CBC vulnerability to escalate privileges from regular user to admin.

**Attack Strategy:**
1. **Cookie Analysis**: Understand the cookie structure and block boundaries
2. **Legitimate Cookie**: Obtain a valid encrypted cookie with `admin=0`
3. **Position Calculation**: Calculate which ciphertext bit to flip
4. **Bit Manipulation**: Flip the bit to change `admin=0` to `admin=1`
5. **Privilege Escalation**: Send modified cookie to gain admin access

**Key Calculations:**
- Target character position in plaintext
- Corresponding ciphertext block to modify
- XOR mask to change '0' to '1'

#### [`bitflippling_video.py`](bitflippling_video.py)
**Stream Cipher Bit-Flipping Demonstration**

This script demonstrates bit-flipping attacks against stream ciphers (ChaCha20), showing how the same principles apply to different encryption modes.

**Attack Process:**
1. **Known Plaintext**: Attacker knows specific characters at known positions
2. **Bit Calculation**: Calculate XOR mask for character change
3. **Ciphertext Modification**: Apply mask to ciphertext
4. **Result Verification**: Decrypt to verify the character change

**Educational Value:**
- Shows bit-flipping attacks work on stream ciphers too
- Demonstrates the mathematical relationship between plaintext and ciphertext
- Illustrates the importance of authenticated encryption modes

## Attack Methodology

### Step 1: Structure Analysis
```python
# Analyze the cookie structure
cookie = b'username=aldooo11,admin=0'
padded_cookie = pad(cookie, AES.block_size)

# Block 0: b'username=aldooo1'
# Block 1: b'1,admin=0\x06\x06\x06\x06\x06\x06'
```

### Step 2: Position Calculation
```python
# Find position of target character
target_position = cookie.index(b'0')  # Position of '0' in 'admin=0'
target_block = target_position // AES.block_size  # Which block contains it
position_in_block = target_position % AES.block_size  # Position within block
```

### Step 3: Bit-Flip Calculation
```python
# Calculate which ciphertext bit to flip
ciphertext_block_to_modify = target_block - 1  # Previous block
ciphertext_byte_position = ciphertext_block_to_modify * AES.block_size + position_in_block

# Calculate XOR mask to change '0' to '1'
xor_mask = ord('0') ^ ord('1')  # ASCII 48 XOR ASCII 49 = 1
```

### Step 4: Attack Execution
```python
# Modify the ciphertext
modified_cookie = bytearray(encrypted_cookie)
modified_cookie[ciphertext_byte_position] ^= xor_mask

# Send modified cookie back to server
server.send(bytes(modified_cookie))
```

## Security Implications

### Why This Attack Works:
1. **CBC Mode Properties**: Mathematical relationship between blocks
2. **No Integrity Check**: Server doesn't verify cookie integrity
3. **Predictable Structure**: Known cookie format enables precise targeting
4. **Insufficient Authentication**: Encryption alone doesn't provide authentication

### Real-World Impact:
- **Privilege Escalation**: Change user roles or permissions
- **Data Manipulation**: Modify financial amounts or other critical data
- **Authentication Bypass**: Alter login credentials or session tokens
- **Access Control Bypass**: Modify access permissions or user levels

## Defensive Measures

### Proper Solutions:
1. **Authenticated Encryption**: Use GCM, CCM, or ChaCha20-Poly1305
2. **HMAC Protection**: Add HMAC to detect tampering
3. **Digital Signatures**: Use RSA or ECDSA for strong authentication
4. **Proper Key Management**: Use different keys for encryption and authentication

### Code Example (Secure Approach):
```python
# Instead of just encrypting:
ciphertext = cipher.encrypt(plaintext)

# Use authenticated encryption:
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

## Common Configuration Files

- **[`myconfig.py`](myconfig.py)**: Server connection settings
- **[`mysecrets.py`](mysecrets.py)**: Cryptographic keys and IVs

## Running the Exercises

### Prerequisites:
```bash
pip install pycryptodome pwn
```

### Basic Usage:
```bash
# Terminal 1: Start the vulnerable server
python3 bf_server_cbc.py

# Terminal 2: Run the bit-flipping attack
python3 bf_client.py
```

### Stream Cipher Demo:
```bash
# Demonstrate stream cipher bit-flipping
python3 bitflippling_video.py
```
