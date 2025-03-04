# Symmetric Encryption

## Overview

In this exercise, you will explore symmetric encryption using OpenSSL in C. You’ll learn how to encrypt and decrypt data with various cipher modes, and understand how to manage encryption contexts through OpenSSL’s EVP API. This exercise is essential for understanding how confidentiality is maintained in secure communications.

## Objectives

- **Understand the Concept:** Learn the fundamentals of symmetric encryption, including block versus stream ciphers, the role of secret keys, and common cipher modes (e.g., ECB, CBC, OFB, CFB).
- **Practical Implementation:** Write or analyze C code that uses OpenSSL’s EVP API to perform incremental encryption and decryption. Understand how to initialize contexts, update encryption with data fragments, and finalize the process.
- **Security Insights:** Recognize important design decisions such as padding (e.g., PKCS#5) and the careful selection of cipher modes. Understand the importance of proper key management and error handling in encryption routines.

## Exercise Details

- **Topic:** Symmetric Encryption
- **Language:** C
- **Tools/Libraries:** OpenSSL

### Background

- **Symmetric Encryption Basics:** Symmetric encryption ensures confidentiality by requiring that only entities with the correct secret key can decrypt data. Popular algorithms include AES and ChaCha20, which differ in their design (block vs. stream).
- **Cipher Modes and Padding:** Block ciphers require decisions on padding (typically PKCS#5) and mode of operation (e.g., CBC, ECB). These decisions affect both the security and efficiency of the encryption process.
- **Incremental Encryption with EVP API:** OpenSSL’s EVP API provides a unified interface for various encryption algorithms. The process involves:
  - Initializing an encryption/decryption context (using functions like `EVP_EncryptInit`/`EVP_DecryptInit`).
  - Processing data incrementally with `EVP_EncryptUpdate`/`EVP_DecryptUpdate`.
  - Finalizing the process with `EVP_EncryptFinal`/`EVP_DecryptFinal`.
- **Cipher Object Loading:** Symmetric ciphers are represented as objects (e.g., `EVP_aes_128_cbc`, `EVP_bf_cbc`) that are loaded into the context. This modular approach allows easy switching between algorithms as needed.

## Instructions

1. **Setup:**  
   - Install OpenSSL on your system.
   - Compile your C code with OpenSSL support (e.g., `gcc -o symm_encrypt symm_encrypt.c -lcrypto`).
   
2. **Implementation:**
   - Initialize an encryption context using the EVP API with your chosen cipher (e.g., AES, Blowfish).
   - Use `EVP_EncryptInit` (or `EVP_CipherInit`) to configure the context with the key, IV, and mode.
   - Process the plaintext in fragments using `EVP_EncryptUpdate`.
   - Finalize encryption with `EVP_EncryptFinal` to ensure all data is processed.
   - Implement the corresponding decryption steps using `EVP_DecryptInit`, `EVP_DecryptUpdate`, and `EVP_DecryptFinal`.
   - Incorporate error handling to manage potential issues during encryption or decryption.
   
3. Testing:
   - Run your program to encrypt and then decrypt sample data.
   - Verify that the decrypted output matches the original plaintext.
   - Test edge cases (such as incorrect keys or improper padding) to ensure robust error handling.
   
## Resources

<!-- - [Course Slides on Cryptography Exercises]() -->
- [Official OpenSSL Documentation](https://www.openssl.org/docs/)
