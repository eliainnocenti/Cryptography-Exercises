# Asymmetric Cryptography Exercises

This directory contains Python scripts demonstrating various asymmetric cryptography techniques using both `PyCryptodome` and `cryptography` libraries. Below is a description of each file:

### [`01_primes.py`](01_primes.py)
Trivial RSA implementation demonstrating the mathematical foundations of RSA:
- Prime number generation using `Crypto.Util.number`
- RSA key pair generation (public and private keys)
- Manual encryption and decryption operations
- Verification of key generation correctness

### [`02_RSA_pycryptodome.py`](02_RSA_pycryptodome.py)
Comprehensive RSA operations using the PyCryptodome library:
- RSA key generation and PEM serialization
- Key import/export with password protection
- RSA-PSS digital signature creation and verification
- RSA-OAEP encryption and decryption
- Key parameter extraction and reconstruction

### [`03_RSA_keygen_hazmat.py`](03_RSA_keygen_hazmat.py)
RSA key generation using the `cryptography` library (hazmat):
- Key pair generation with configurable parameters
- PEM serialization with optional password protection
- Public key extraction and parameter display
- File-based key storage and management

### [`04_RSA_signature_hazmat.py`](04_RSA_signature_hazmat.py)
RSA digital signatures using the `cryptography` library:
- RSA-PSS signature creation and verification
- Direct message signing
- Prehashed data signing for large datasets
- Signature verification with error handling

### [`05_RSA_encrypt_hazmat.py`](05_RSA_encrypt_hazmat.py)
RSA encryption using the `cryptography` library:
- Loading RSA keys from PEM files
- RSA-OAEP encryption and decryption
- Secure key generation as fallback
- Constant-time comparison for security

### [`06_DH_simulate_protocol.py`](06_DH_simulate_protocol.py)
Diffie-Hellman key exchange protocol simulation:
- DH parameter generation and key exchange
- Shared secret derivation and verification
- Key derivation using both PyCryptodome and cryptography libraries
- Multiple key exchange rounds with ephemeral keys
- Forward secrecy demonstration

### [`07_DHE.py`](07_DHE.py)
Diffie-Hellman Ephemeral (DHE) key exchange:
- Proper DHE implementation with parameter reuse
- Ephemeral key generation for each handshake
- HKDF-based key derivation
- Forward secrecy verification
- Multiple handshake demonstration

## Key Concepts Demonstrated

- **RSA Key Operations**: Generation, serialization, import/export
- **Digital Signatures**: RSA-PSS with SHA-256 hashing
- **Asymmetric Encryption**: RSA-OAEP for secure message encryption
- **Key Exchange**: Diffie-Hellman for shared secret establishment
- **Key Derivation**: HKDF for deriving multiple keys from shared secrets
- **Security Best Practices**: Ephemeral keys, forward secrecy, secure comparison

## Libraries Used

- **PyCryptodome**: High-level cryptographic operations
- **cryptography**: Low-level cryptographic primitives (hazmat)
- Both libraries demonstrate different approaches to the same cryptographic operations

## Security Notes

- All implementations use recommended key sizes (2048+ bits for RSA, 1024+ bits for DH)
- Proper padding schemes (PSS for signatures, OAEP for encryption)
- Secure random number generation for all cryptographic material
- Forward secrecy through ephemeral key usage in DH exchanges
