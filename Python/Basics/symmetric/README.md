# Symmetric Cryptography Exercises

This directory contains Python scripts demonstrating various symmetric cryptography techniques using the `PyCryptodome` library. 
Below is a description of each file:

### [`01.gen_random_key.py`](01.gen_random_key.py)
This script demonstrates how to generate random bytes using `get_random_bytes`. It generates:
- A 40-byte random key.
- A random value equal to the AES block size (16 bytes).

### [`02.block_AES_padding.py`](02.block_AES_padding.py)
This script demonstrates AES encryption in CBC mode with and without padding:
- Encrypts aligned and unaligned data.
- Uses `pad` and `unpad` utilities to handle padding for unaligned data.
- Prints Base64-encoded ciphertext for easier readability.

### [`03.stream_chacha20.py`](03.stream_chacha20.py)
This script demonstrates ChaCha20 stream cipher encryption:
- Encrypts a plaintext message.
- Automatically generates a nonce or allows manual nonce selection.
- Prints the ciphertext and nonce in Base64 format.

### [`04.stream_salsa_incremental.py`](04.stream_salsa_incremental.py)
This script demonstrates incremental encryption using the Salsa20 stream cipher:
- Encrypts a message in parts.
- Prints the nonce for decryption.
- Verifies decryption by reconstructing the original plaintext.

### [`05.stream_encrypt_file_update.py`](05.stream_encrypt_file_update.py)
This script encrypts a file using the Salsa20 stream cipher:
- Reads the input file in chunks.
- Encrypts each chunk and writes the ciphertext to an output file.
- Prints the nonce in Base64 format for decryption.

### [`06.AES_encrypt_file.py`](06.AES_encrypt_file.py)
This script encrypts the content of a file using AES in CBC mode:
- Generates a random AES key and IV.
- Pads the file content to match the AES block size.
- Writes the ciphertext to an output file.

### [`07.stream_json.py`](07.stream_json.py)
This script demonstrates ChaCha20 encryption with JSON serialization:
- Encrypts a plaintext message.
- Stores the nonce and ciphertext in a JSON object.
- Decrypts the ciphertext using the stored nonce.

### [`08.sha256.py`](08.sha256.py)
This script demonstrates hashing using SHA-256:
- Hashes a message in parts.
- Prints the digest and hexadecimal digest.

### [`09.hash_file_sha3.py`](09.hash_file_sha3.py)
This script demonstrates file hashing using SHA3-256:
- Hashes the content of the current script file in text and binary modes.
- Prints the digest and hexadecimal digest.

### [`10.hmac_sha512.py`](10.hmac_sha512.py)
This script demonstrates HMAC generation and verification using SHA-512:
- Computes an HMAC for a message.
- Stores the message and HMAC in a JSON object.
- Verifies the HMAC to ensure message authenticity.

### [`11.aead_AES_gcm.py`](11.aead_AES_gcm.py)
This script demonstrates AES encryption in GCM mode:
- Encrypts a message with associated authenticated data.
- Serializes the nonce, header, ciphertext, and tag into a JSON object.
- Verifies the authenticity of the ciphertext during decryption.

### [`12.key_derivation.py`](12.key_derivation.py)
This script demonstrates key derivation using the scrypt algorithm:
- Derives a key from a password and a random salt.
- Prints the salt and derived key.

### [`13.sha256_hashlib.py`](13.sha256_hashlib.py)
This script demonstrates hashing using Python's `hashlib` library:
- Hashes a concatenated message using SHA-256.
- Prints the digest and hexadecimal digest.

### [`14.hmac_hashlib.py`](14.hmac_hashlib.py)
This script demonstrates HMAC generation and verification using Python's `hashlib` library:
- Computes an HMAC for a message using SHA-256.
- Verifies the HMAC to ensure message authenticity.
- Demonstrates how mismatched messages result in verification failure.
