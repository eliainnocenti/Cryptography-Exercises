# Asymmetric Cryptography

## Overview

In this exercise, you will explore asymmetric cryptography using OpenSSL in C, with a focus on RSA. You will learn how to generate RSA keys using the EVP interface, perform encryption and decryption, and create digital signatures. Asymmetric cryptography is essential for secure key exchange, data confidentiality, and authentication.

## Objectives

- **Understand the Concept:** Learn the principles of asymmetric encryption, including RSA key generation, encryption/decryption operations, and digital signatures using the EVP API.
- **Practical Implementation:** Write or analyze C code that uses OpenSSL’s EVP interface to generate RSA keys, encrypt data with the public key, decrypt data with the private key, and sign messages with digital signatures.
- **Security Insights:** Recognize the importance of using proper padding schemes (e.g., `RSA_PKCS1_OAEP_PADDING`), secure key management, and robust error handling with OpenSSL’s error functions.

## Exercise Details

- **Topic:** Asymmetric Encryption
- **Language:** C
- **Tools/Libraries:** OpenSSL

### Background

- **EVP Interface for Asymmetric Algorithms:** OpenSSL’s EVP API provides a high-level and unified interface for asymmetric cryptographic operations. It simplifies the use of algorithms such as RSA, DSA, DH, and EC. In OpenSSL 3.0, using EVP is mandatory for key generation and other asymmetric operations.
- **RSA Key Generation:** RSA keys are generated using functions like `EVP_PKEY_CTX_new_from_name`, `EVP_PKEY_keygen_init`, and `EVP_PKEY_generate`. You can adjust parameters such as key size and number of primes to suit your security requirements.
- **Encryption/Decryption and Padding:** RSA encryption is performed with functions such as `RSA_public_encrypt` (using the public key) and `RSA_private_decrypt` (using the private key). Choosing the right padding (e.g., `RSA_PKCS1_OAEP_PADDING`) is critical for ensuring security.
- **Digital Signatures:** The `EVP_DigestSign*` API allows you to create digital signatures. The process involves initializing a digest context, updating it with your message, and finalizing the signature. This ensures data integrity and authentication.

## Instructions

1. **Setup:**  
   - Ensure that OpenSSL is installed on your system.
   - Include the necessary headers (e.g., `<openssl/evp.h>`, `<openssl/rsa.h>`, `<openssl/pem.h>`).
   - Compile your C code with OpenSSL support (e.g., `gcc -o asymm_crypto asymm_crypto.c -lcrypto`).
   
2. **Implementation:**
   - **RSA Key Generation Example:**
     ```c
     EVP_PKEY *pkey = NULL;
     EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
     if (!pctx) {
        // Handle error
     }
     if (EVP_PKEY_keygen_init(pctx) <= 0) {
        // Handle error
     }
     // Set key parameters (e.g., 2048 bits)
     OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_uint("bits", (unsigned int[]){2048}),
        OSSL_PARAM_construct_end()
     };
     if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        // Handle error
     }
     if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        // Handle error
     }
     EVP_PKEY_CTX_free(pctx);
     // 'pkey' now contains the generated RSA key pair
     ```
   - **RSA Encryption and Decryption:**
     - Encrypt data using the public key with `RSA_public_encrypt`, ensuring you select an appropriate padding mode (e.g., `RSA_PKCS1_OAEP_PADDING`).
     - Decrypt data using the private key with `RSA_private_decrypt`.
     - *Example pseudocode:*
     ```c
     int encrypted_len = RSA_public_encrypt(plaintext_len, plaintext, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
     if (encrypted_len == -1) {
        // Handle encryption error
     }
     int decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
     if (decrypted_len == -1) {
        // Handle decryption error
     }
     ```
   - **Digital Signature Example:**
     ```c
     EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
     if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        // Handle error
     }
     // Update with the message to be signed
     if (EVP_DigestSignUpdate(mdctx, message, message_len) <= 0) {
        // Handle error
     }
     // Finalize the signature; first, obtain the required signature length
     size_t siglen;
     if (EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0) {
        // Handle error
     }
     unsigned char *signature = malloc(siglen);
     if (!signature) {
        // Handle allocation error
     }
     if (EVP_DigestSignFinal(mdctx, signature, &siglen) <= 0) {
        // Handle error
     }
     EVP_MD_CTX_free(mdctx);
     // 'signature' now contains the digital signature
     ```
   - **Error Handling and Resource Management:**
     - Always check return values of OpenSSL functions.
     - Use OpenSSL’s error functions (e.g., `ERR_print_errors_fp(stderr)`) to print error details.
     - Free allocated resources properly to avoid memory leaks.
   
3. Testing:
   - Run your program to generate RSA keys, encrypt a sample message, and then decrypt it to verify that the original message is recovered.
   - Test the digital signature process by signing a message and then verifying the signature.
   - Experiment with different key sizes and padding options to observe their effects on performance and security.
   
## Resources

<!-- - [Course Slides on Cryptography Exercises]() -->
- [Official OpenSSL Documentation](https://www.openssl.org/docs/)
