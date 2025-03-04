# Random Numbers

## Overview

In this exercise, you will explore OpenSSL’s cryptographically secure pseudo-random number generators (PRNGs). You’ll learn how to generate random bytes using OpenSSL functions and why a high-entropy seed is essential for ensuring unpredictability—a key requirement in cryptographic operations.

## Objectives

- **Understand PRNG Concepts:** Learn how OpenSSL’s deterministic random bit generator (DRBG) works and why a strong, unpredictable seed is critical.
- **Practical Implementation:** Develop C code that uses functions such as `RAND_bytes` for general-purpose randomness and `RAND_priv_bytes` for generating private, sensitive random numbers.
- **Security Insights:** RRecognize potential pitfalls—such as using insecure seeds—and follow best practices to prevent predictable output.

## Exercise Details

- **Topic:** Random Number Generation
- **Language:** C
- **Tools/Libraries:** OpenSSL

### Background

- **Cryptographic PRNG:** OpenSSL provides a PRNG that, while deterministic, produces output indistinguishable from true randomness when properly seeded.
- **Importance of Seeding:** The security of the PRNG hinges on a high-entropy seed. Using a weak seed can lead to predictable random numbers, compromising cryptographic security. It is often recommended to seed the PRNG from a reliable entropy source (e.g., `/dev/random`) using functions like `RAND_load_file`.
- **Core Functions:** 
  - `RAND_bytes(unsigned char *buf, int num)`: Generates `num` random bytes and stores them in `buf`.
  - `RAND_priv_bytes(unsigned char *buf, int num)`: Similar to `RAND_bytes`, but intended for generating private random numbers that remain internal to the application.

## Instructions
1. **Setup:**  
   - Ensure that OpenSSL is installed on your system.
   - Compile your C code with OpenSSL (e.g., using `gcc -o random_example random_example.c -lcrypto`).
   
2. **Implementation:**
   - Use `RAND_bytes` to generate public random data.
   - Use `RAND_priv_bytes` when generating private random values.
   - Optionally, seed the PRNG manually (especially on systems where automatic seeding may not be sufficient) by calling:
      ```c
      int rc = RAND_load_file("/dev/random", 32);
      if(rc != 32) {
         // Handle seeding error appropriately
      }
      ```
   - Incorporate proper error handling to ensure that the PRNG is initialized and used securely.
   
3. Testing:
   - Run your compiled program and verify that it outputs the expected random bytes.
   - Test error conditions (e.g., failed seeding) to ensure robust handling.
   
## Resources

<!-- - [Course Slides on Cryptography Exercises]() -->
<!-- - [OpenSSL Random Numbers Slide]() -->
- [Official OpenSSL Documentation](https://www.openssl.org/docs/)
