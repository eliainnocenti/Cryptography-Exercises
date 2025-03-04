# Digests and MACs

## Overview

In this exercise, you will explore how to compute cryptographic digests (hashes) and MACs (Message Authentication Codes) using OpenSSL in C. You’ll learn to process data incrementally to generate digests and to create HMACs for both data integrity and authenticity.

## Objectives

- **Understand the Concept:** Learn the fundamentals of cryptographic hash functions, incremental hashing, and keyed digests (HMACs), which ensure that data has not been tampered with and comes from a trusted source.
- **Practical Implementation:** Write or analyze C code that uses OpenSSL’s EVP API to compute digests and HMACs. Implement the incremental approach to process data in fragments and finalize the hash computation.
- **Security Insights:** Understand potential pitfalls such as timing attacks when comparing digests. Use secure functions like `CRYPTO_memcmp` for constant-time comparisons and implement robust error handling with OpenSSL’s error management routines.

## Exercise Details

- **Topic:** Digests, MACs and HMACs
- **Language:** C
- **Tools/Libraries:** OpenSSL

### Background

- **Digest Computation:** A digest (hash) is a fixed-size output derived from an input message. OpenSSL computes hashes incrementally—first initializing a context, then updating it with data fragments, and finally finalizing to produce the digest. This process makes handling large or streaming data efficient.
- **Incremental Hashing with EVP API:** The EVP API provides a unified interface for all supported hash algorithms:
  - **Initialization:** Create a context using `EVP_MD_CTX_new` and initialize it with `EVP_DigestInit` (e.g., using SHA1).
  - **Update:** Process data in segments with `EVP_DigestUpdate`.
  - **Finalize:** Call `EVP_DigestFinal` to retrieve the digest.
- **Keyed Digests (HMACs):** HMACs add a secret key to the hashing process, ensuring both integrity and authenticity. OpenSSL supports HMAC computation using either a dedicated HMAC function or via an incremental approach similar to plain digest computation.
- **Security Considerations:** For secure digest comparison, avoid using standard functions like `memcmp` that may leak timing information. Instead, use `CRYPTO_memcmp` for constant-time comparisons. Also, consistently check return values and manage errors using OpenSSL functions like `ERR_print_errors_fp`.

## Instructions

1. **Setup:**  
   - Ensure that OpenSSL is installed on your system.
   - Compile your C code with OpenSSL support (e.g., `gcc -o digest_mac digest_mac.c -lcrypto`).
   
2. **Implementation:**
   - **Digest Calculation:**
     - Initialize a digest context:
       ```c
       EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
       if (!md_ctx) handleErrors();
       ```
     - Set up the desired hash algorithm (e.g., SHA1):
       ```c
       if (1 != EVP_DigestInit(md_ctx, EVP_sha1()))
          handleErrors();
       ```
     - Incrementally update the context with data:
       ```c
       if (1 != EVP_DigestUpdate(md_ctx, plaintext_fragment, fragment_len))
          handleErrors();
       ```
     - Finalize and retrieve the digest:
       ```c
       unsigned char digest[EVP_MAX_MD_SIZE];
       unsigned int digest_len;
       if (1 != EVP_DigestFinal(md_ctx, digest, &digest_len))
          handleErrors();
       EVP_MD_CTX_free(md_ctx);
       ```
   - **HMAC Computation (Keyed Digest):**
     - Initialize a context for HMAC with a secret key:
       ```c
       HMAC_CTX *hmac_ctx = HMAC_CTX_new();
       if (!hmac_ctx) handleErrors();
       if (1 != HMAC_Init_ex(hmac_ctx, key, key_len, EVP_sha1(), NULL))
          handleErrors();
       ```
     - Process the data incrementally:
       ```c
       if (1 != HMAC_Update(hmac_ctx, plaintext_fragment, fragment_len))
          handleErrors();
       ```
     - Finalize to obtain the HMAC:
       ```c
       unsigned char hmac_value[EVP_MAX_MD_SIZE];
       unsigned int hmac_len;
       if (1 != HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
          handleErrors();
       HMAC_CTX_free(hmac_ctx);
       ```
   - **Verification and Error Handling:**
     - Compare computed digests using `CRYPTO_memcmp` to mitigate timing attacks:
       ```c
       if (CRYPTO_memcmp(computed_digest, expected_digest, digest_len) != 0) {
          // Handle mismatch
       }
       ```
     - Implement error handling using OpenSSL’s error functions:
       ```c
       void handleErrors(void) {
          ERR_print_errors_fp(stderr);
          abort();
       }
       ```
   
3. Testing:
   - Run your program to compute and verify both the digest and the HMAC of sample data.
   - Confirm that the computed outputs match expected values.
   - Test edge cases, such as processing data in multiple fragments and handling incorrect keys, to ensure robust error handling.
   
## Resources

<!-- - [Course Slides on Cryptography Exercises]() -->
- [Official OpenSSL Documentation](https://www.openssl.org/docs/)
