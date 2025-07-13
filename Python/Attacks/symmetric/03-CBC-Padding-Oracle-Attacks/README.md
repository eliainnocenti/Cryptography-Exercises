# CBC Padding Oracle Attacks

This directory contains a comprehensive demonstration of CBC (Cipher Block Chaining) padding oracle attacks, one of the most devastating cryptographic attacks that exploits information leakage in padding validation.

## Overview

A padding oracle attack is a type of side-channel attack that exploits the information leaked by a cryptographic system when it validates padding. In CBC mode, when a server reveals whether the padding of a decrypted message is valid or not, an attacker can systematically decrypt arbitrary ciphertexts without knowing the encryption key.

## Attack Mechanism

### CBC Mode Vulnerability

In CBC mode encryption:
- `P_i = D_K(C_i) ⊕ C_{i-1}` (decryption)
- `C_i = E_K(P_i ⊕ C_{i-1})` (encryption)

The vulnerability arises when:
1. The server decrypts a ciphertext
2. Validates the padding (PKCS#7)
3. **Leaks information** about whether the padding is valid

### Attack Process

1. **Target Selection**: Choose the last two blocks of ciphertext
2. **Byte Manipulation**: Systematically modify bytes in the second-to-last block
3. **Oracle Query**: Send modified ciphertext to the server
4. **Response Analysis**: Determine if padding is valid based on server response
5. **Plaintext Recovery**: Use XOR relationships to recover plaintext bytes
6. **Iteration**: Repeat for all bytes in the block

### Mathematical Foundation

For the last byte attack:
- If modified ciphertext produces valid padding `0x01`
- Then: `P'[15] = 0x01 = D_K(C[15]) ⊕ C'[14]`
- So: `D_K(C[15]) = 0x01 ⊕ C'[14]`
- Original plaintext: `P[15] = D_K(C[15]) ⊕ C[14]`

## Files Description

### Server Components
- **`CBCPaddingOracle_Server.py`**: Vulnerable server that leaks padding validation information
- **`myconfig.py`**: Network configuration (host, port, timeouts)
- **`mysecrets.py`**: Secret encryption key (unknown to attacker in real scenario)

### Attack Components
- **`CBCPaddingOracle_client.py`**: Fixed client implementation for the attack
- **`CBC_PaddingOracle_Attack_video.py`**: Educational attack demonstration script
- **`mydata.py`**: Test data including IV and target ciphertext

### Utilities
- **`helper/gen_ciphertext.py`**: Helper script to generate test ciphertexts

## Usage Instructions

### 1. Start the Vulnerable Server

```bash
python CBCPaddingOracle_Server.py
```

The server will start listening on `localhost:12346` and provide padding validation services.

### 2. Run the Attack

```bash
python CBC_PaddingOracle_Attack_video.py
```

This demonstrates the attack by:
- Analyzing the ciphertext structure
- Attacking the last byte of the target block
- Attacking the second-to-last byte
- Showing the recovered plaintext bytes

### 3. Generate New Test Data (Optional)

```bash
python helper/gen_ciphertext.py
```

This creates new test ciphertexts for experimentation.

## Attack Results

The attack successfully recovers plaintext bytes by exploiting the padding oracle:

```
=== Attack Results ===
Last byte (pos 15): 125 ('}')
Second-to-last byte (pos 14): 63 ('?')
Partial plaintext (last 2 bytes): b'?}'
```

## Security Implications

### Why This Attack Works

1. **Information Leakage**: Server reveals padding validity
2. **Deterministic Process**: Same input always produces same output
3. **Bit-by-bit Recovery**: Each byte can be recovered independently
4. **No Key Required**: Attack works without knowing the encryption key

### Real-World Impact

- **Complete Decryption**: Entire messages can be decrypted
- **Session Hijacking**: Encrypted session tokens can be compromised
- **Data Exfiltration**: Sensitive information can be extracted
- **Authentication Bypass**: Encrypted authentication data can be manipulated

## Defensive Measures

### 1. Use Authenticated Encryption
```python
# Instead of CBC, use GCM mode
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

### 2. Implement Constant-Time Operations
```python
# Always take the same amount of time regardless of padding validity
def constant_time_compare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
```

### 3. Don't Leak Padding Information
```python
# Generic error message
try:
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
except ValueError:
    return "Decryption failed"  # Don't specify why
```

### 4. Use Modern Cryptographic Libraries
- Prefer libraries that provide authenticated encryption by default
- Avoid implementing custom padding validation
- Use well-tested cryptographic primitives

## Common Variations

1. **Timing Attacks**: Different response times for valid/invalid padding
2. **Error Message Attacks**: Different error messages leak information
3. **TCP Reset Attacks**: Connection behavior reveals padding validity
4. **Side-Channel Attacks**: Power consumption or electromagnetic emanations

## Testing and Validation

To verify the attack implementation:

1. Start the server
2. Run the attack script
3. Observe byte-by-byte decryption
4. Compare with expected plaintext
5. Experiment with different ciphertexts
