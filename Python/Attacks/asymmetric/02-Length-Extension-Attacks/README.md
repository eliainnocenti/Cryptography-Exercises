# Length Extension Attacks - Hash Function Vulnerabilities

This directory contains implementations of length extension attacks against hash functions that use the Merkle-Damgård construction, specifically MD5 and SHA-1. These attacks demonstrate critical vulnerabilities in naive authentication schemes.

## Overview

Length extension attacks exploit the internal structure of hash functions based on the Merkle-Damgård construction. These attacks allow an attacker to append data to a message and compute the hash of the extended message without knowing the original message or secret key.

## Attack Fundamentals

### The Merkle-Damgård Construction

Most classical hash functions (MD5, SHA-1, SHA-2) use the Merkle-Damgård construction:
1. **Initialization**: Start with an initial hash value (IV)
2. **Padding**: Add padding to make the message length a multiple of the block size
3. **Compression**: Process message blocks sequentially, updating the internal state
4. **Output**: The final internal state becomes the hash output

### Vulnerability

The vulnerability arises because:
- The final hash reveals the internal state of the hash function
- An attacker can resume computation from this known state
- New data can be appended and hashed without knowing the original message

## Vulnerable Authentication Schemes

### Naive Scheme: H(secret||message)
```python
# VULNERABLE: Simple concatenation
def vulnerable_auth(secret, message):
    return hash(secret + message)
```

This scheme is vulnerable because:
1. Attacker knows the hash H(secret||message)
2. Attacker can compute H(secret||message||padding||extension)
3. Attacker can forge authenticated messages

### Secure Alternative: HMAC
```python
# SECURE: HMAC construction
def secure_auth(secret, message):
    return hmac(secret, message)
```

HMAC is secure because it uses a double-hash construction that prevents length extension attacks.

## Attack Implementations

### 1. **SHA-1 Length Extension** (`sha1.py`)
- **Target**: SHA-1 hash function
- **Method**: Resume computation from known hash state
- **Demonstration**: Forge authentication tokens
- **Educational Value**: Understanding hash function internals

### 2. **MD5 Length Extension** (`pymd5.py`)
- **Target**: MD5 hash function
- **Method**: Pure Python implementation with state manipulation
- **Demonstration**: Message forgery without secret knowledge
- **Educational Value**: Hands-on hash function implementation

## Quick Start

### Prerequisites
```bash
# No additional dependencies required
# Both implementations are pure Python
```

### Running the Attacks

#### SHA-1 Length Extension Attack
```bash
python sha1.py
```

#### MD5 Length Extension Attack
```bash
python pymd5.py
```

### Example Attack Scenario

```python
# Original authentication
secret = b'secret_key_123'
message = b'user=admin&action=view'
original_hash = sha1(secret + message).hexdigest()

# Attacker's goal: forge message with additional data
extension = b'&action=delete&target=all'

# Length extension attack
# 1. Determine padding for original message
padding = calculate_padding(len(secret + message))

# 2. Initialize hash with known state
attack_hash = SHA1(original_hash)

# 3. Append new data
attack_hash.update(extension)

# 4. Get forged hash
forged_hash = attack_hash.hexdigest()

# Result: Hash of secret||message||padding||extension
```

## Mathematical Foundation

### Padding Calculation
For SHA-1 and MD5, the padding scheme is:
1. Append a single '1' bit (0x80 byte)
2. Append zero bits until message length ≡ 448 (mod 512)
3. Append the original message length as a 64-bit big-endian integer

### State Reconstruction
The hash output directly reveals the internal state:
- **SHA-1**: 5 × 32-bit words (160 bits total)
- **MD5**: 4 × 32-bit words (128 bits total)

### Extension Process
1. Parse the known hash into internal state words
2. Set the bit counter to account for the original message + padding
3. Process the extension data through the compression function
4. Output the final hash

## Security Implications

### Attack Scenarios

#### Scenario 1: Cookie Forgery
```python
# Original cookie: user=guest&role=user
# Hash: H(secret||"user=guest&role=user")
# Attacker extends: user=guest&role=user[padding]&role=admin
# Forged hash: H(secret||"user=guest&role=user"||padding||"&role=admin")
```

#### Scenario 2: API Parameter Injection
```python
# Original API call: /api/read?file=public.txt
# Hash: H(secret||"/api/read?file=public.txt")
# Attacker extends: /api/read?file=public.txt[padding]&file=../../etc/passwd
```

## Defensive Measures

### 1. Use HMAC
```python
import hmac
import hashlib

def secure_authenticate(secret, message):
    return hmac.new(secret, message, hashlib.sha256).hexdigest()
```

### 2. Length-Prefixed Schemes
```python
def length_prefixed_auth(secret, message):
    length = len(message).to_bytes(8, 'big')
    return hash(secret + length + message)
```

### 3. Modern Hash Functions
```python
# Use SHA-3 (Keccak) - immune to length extension
import hashlib
def sha3_auth(secret, message):
    return hashlib.sha3_256(secret + message).hexdigest()
```

### 4. Authenticated Encryption
```python
# Use AEAD modes like AES-GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def aead_auth(key, message):
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, message, b"")
```

## Vulnerable Hash Functions

### Susceptible to Length Extension
- **MD5**: Completely broken, vulnerable to length extension
- **SHA-1**: Cryptographically broken, vulnerable to length extension
- **SHA-2 Family**: SHA-224, SHA-256, SHA-384, SHA-512 (all vulnerable)

### Immune to Length Extension
- **SHA-3 (Keccak)**: Uses sponge construction, not Merkle-Damgård
- **BLAKE2**: Modern hash function with built-in keying
- **BLAKE3**: Latest generation, immune to length extension

## Code Analysis

### SHA-1 Implementation Features
- **State Management**: Proper handling of internal hash state
- **Padding Logic**: Correct implementation of SHA-1 padding
- **Bit Counting**: Accurate tracking of message length
- **Attack Demo**: Complete length extension attack example

### MD5 Implementation Features
- **Pure Python**: No external dependencies
- **Educational Value**: Clear, commented implementation
- **Compression Function**: Detailed MD5 compression function
- **Testing**: Compatibility with standard library

## Performance Comparison

| Hash Function | Block Size | State Size | Attack Complexity |
|---------------|------------|------------|------------------|
| MD5           | 512 bits   | 128 bits   | O(1) with known hash |
| SHA-1         | 512 bits   | 160 bits   | O(1) with known hash |
| SHA-256       | 512 bits   | 256 bits   | O(1) with known hash |
| SHA-3-256     | 1088 bits  | 256 bits   | Not vulnerable |
