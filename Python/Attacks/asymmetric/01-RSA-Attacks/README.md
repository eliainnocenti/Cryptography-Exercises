# RSA Attacks - Comprehensive Educational Collection

This directory contains implementations of various cryptographic attacks against RSA encryption, demonstrating fundamental vulnerabilities and the importance of proper implementation practices.

## Overview

RSA (Rivest-Shamir-Adleman) is one of the most widely used public-key cryptosystems. While mathematically sound, RSA implementations can be vulnerable to various attacks when not properly implemented or when weak parameters are used.

## Attack Categories

### 1. **FactorDB Attack** (`01-FactorDB/`)
- **Vulnerability**: Using known composite numbers as RSA moduli
- **Attack Method**: Query online databases for known factorizations
- **Lesson**: Never use predictable or known composite numbers

### 2. **Fermat Factorization** (`02-Fermat-Factorization/`)
- **Vulnerability**: RSA moduli where p and q are too close
- **Attack Method**: Exploit the algebraic structure when primes are close
- **Lesson**: Ensure sufficient distance between prime factors

### 3. **Common Primes Attack** (`03-Common-Primes/`)
- **Vulnerability**: Multiple RSA moduli sharing a common prime factor
- **Attack Method**: Compute GCD of different moduli to find shared factors
- **Lesson**: Never reuse prime factors across different key pairs

### 4. **Common Modulus Attack** (`04-Common-Modulus/`)
- **Vulnerability**: Same modulus used with different public exponents
- **Attack Method**: Exploit Bézout's identity to decrypt without private key
- **Lesson**: Never share the same modulus across different key pairs

### 5. **Low Public Exponent Attack** (`05-Low-Public-Exponent/`)
- **Vulnerability**: Very small public exponents (e=3) with unpadded messages
- **Attack Method**: Direct computation of small roots
- **Lesson**: Always use proper padding schemes (OAEP)

### 6. **Håstad's Broadcast Attack** (`06-Hastad-Broadcast/`)
- **Vulnerability**: Broadcasting the same message to multiple recipients with e=3
- **Attack Method**: Chinese Remainder Theorem to compute cube roots
- **Lesson**: Use proper randomized padding for all messages

### 7. **LSB Oracle Attack** (`07-LSB-Oracle/`)
- **Vulnerability**: Leaking the least significant bit of decrypted ciphertexts
- **Attack Method**: Binary search using parity information
- **Lesson**: Never leak partial information about plaintexts

## Quick Start

### Prerequisites
```bash
pip install pwntools  # For network communication in LSB Oracle attack
pip install requests  # For FactorDB queries
```

### Running Individual Attacks

Each attack directory contains:
- `attack.py` - Main attack implementation
- Supporting files (keys, configuration, etc.)
- Individual documentation

Example usage:
```bash
# Navigate to specific attack directory
cd 01-FactorDB/
python attack.py

# For LSB Oracle attack, start server first
cd 07-LSB-Oracle/
python LSB_Oracle.py &  # Start server in background
python LSB_Oracle_client.py  # Run client attack
```

## Educational Goals

### Understanding RSA Vulnerabilities
- **Mathematical Weaknesses**: Learn how poor parameter choices lead to attacks
- **Implementation Flaws**: Understand side-channel vulnerabilities
- **Cryptographic Principles**: Grasp the importance of proper padding and randomization

### Security Best Practices
- **Key Generation**: Proper prime selection and validation
- **Padding Schemes**: Always use OAEP or similar robust padding
- **Side-Channel Protection**: Implement constant-time operations
- **Parameter Validation**: Verify all cryptographic parameters

## Attack Complexity Analysis

| Attack | Time Complexity | Space Complexity | Practical Threshold |
|--------|----------------|------------------|-------------------|
| FactorDB | O(1) | O(1) | Any known modulus |
| Fermat | O(√\|p-q\|) | O(1) | \|p-q\| < 2^(n/4) |
| Common Primes | O(log n) | O(1) | Any shared prime |
| Common Modulus | O(log n) | O(1) | gcd(e₁,e₂) = 1 |
| Low Exponent | O(e) | O(1) | Small e, no padding |
| Håstad | O(k³) | O(k) | k messages, e=3 |
| LSB Oracle | O(n) | O(1) | n-bit modulus |

## Defensive Measures

### Implementation Guidelines
1. **Use Established Libraries**: Don't implement RSA from scratch
2. **Proper Key Generation**: Use cryptographically secure random number generators
3. **Adequate Key Sizes**: Minimum 2048-bit keys, preferably 3072-bit or higher
4. **Mandatory Padding**: Always use OAEP for encryption, PSS for signatures
5. **Side-Channel Protection**: Implement blinding and constant-time operations

### Migration Strategies
1. **Hybrid Cryptography**: Combine RSA with symmetric encryption
2. **Elliptic Curve Cryptography**: Consider ECC for new systems
3. **Post-Quantum Cryptography**: Prepare for quantum-resistant algorithms
4. **Perfect Forward Secrecy**: Use ephemeral key exchange methods

## Code Structure

```
01-RSA-Attacks/
├── README.md                      # This file
├── 01-FactorDB/
│   ├── attack.py                  # FactorDB attack implementation
│   └── vulnerable_keys.py         # Sample vulnerable keys
├── 02-Fermat-Factorization/
│   ├── attack.py                  # Fermat's factorization method
│   └── generate_close_primes.py   # Generate vulnerable keys
├── 03-Common-Primes/
│   ├── attack.py                  # GCD-based attack
│   └── common_prime_keys.py       # Sample keys with shared primes
├── 04-Common-Modulus/
│   ├── attack.py                  # Common modulus attack
│   └── shared_modulus_keys.py     # Sample keys with shared modulus
├── 05-Low-Public-Exponent/
│   ├── attack.py                  # Low exponent attack
│   └── low_e_keys.py              # Sample keys with e=3
├── 06-Hastad-Broadcast/
│   ├── attack.py                  # Håstad's broadcast attack
│   └── broadcast_scenario.py      # Sample broadcast scenario
└── 07-LSB-Oracle/
    ├── LSB_Oracle.py              # Vulnerable oracle server
    ├── LSB_Oracle_client.py       # Attack client
    ├── LSB_Oracle_client_Decimal.py # High-precision attack client
    ├── mysecrets.py               # RSA key material
    └── myconfig.py                # Network configuration
```
