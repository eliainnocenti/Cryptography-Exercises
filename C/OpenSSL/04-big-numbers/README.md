# Big Numbers

## Overview

In this exercise, you will explore how OpenSSL represents and manipulates large integers using its BIGNUM library. This module is essential for public-key cryptography, where numbers often exceed the capacity of standard C data types. You will learn how to perform arbitrary-precision arithmetic and understand its applications in cryptographic algorithms such as RSA and Diffie-Hellman.

## Objectives

- **Understand the Concept:** Learn how OpenSSL’s BIGNUM data structure represents large integers and why arbitrary-precision arithmetic is vital for cryptography.
- **Practical Implementation:** Write or analyze C code that creates, manipulates, and converts BIGNUMs using functions like `BN_new`, `BN_copy`, `BN_dup`, `BN_bn2bin`, and arithmetic operations (e.g., `BN_add`, `BN_mod_exp`).
- **Security Insights:** Recognize the importance of correct memory management and deep copying when handling BIGNUMs. Understand how proper conversion and arithmetic operations ensure reliable cryptographic computations.

## Exercise Details

- **Topic:** Big Numbers
- **Language:** C
- **Tools/Libraries:** OpenSSL

### Background

- **Arbitrary Precision Arithmetic:** Standard C data types (32/64-bit) are insufficient for the large integers used in cryptography. The BIGNUM library supports integers of virtually any size, allocating memory dynamically as needed.
- **BIGNUM Usage:** BIGNUMs are used to represent key components in RSA, DH, and other cryptographic systems. The library provides functions to create, copy, and convert these numbers:
  - **Creation and Memory Management:** Use `BN_new` to allocate and `BN_free` to release BIGNUMs.
  - **Copying:** Use `BN_copy` for deep copying and `BN_dup` to duplicate an existing BIGNUM.
  - **Conversions:** Convert BIGNUMs to binary with `BN_bn2bin` or to human-readable forms (decimal/hexadecimal) for debugging or storage.
  - **Arithmetic Operations:** Perform operations such as addition, multiplication, division, and modular arithmetic essential for cryptographic computations.

## Instructions

1. **Setup:**  
   - Ensure that OpenSSL is installed on your system.
   - Include the header `<openssl/bn.h>` in your C source files.
   - Compile your C code with OpenSSL support (e.g., `gcc -o bignum_example bignum_example.c -lcrypto`).
   
2. **Implementation:**
   - **Creating and Freeing BIGNUMs:**
     ```c
     BIGNUM *bn = BN_new();
     if (bn == NULL) {
        // Handle error
     }
     // ... use bn ...
     BN_free(bn);
     ```
   - **Copying BIGNUMs:**
     ```c
     BIGNUM *a = BN_new();
     BIGNUM *b = BN_new();
     // Initialize 'a' with a value (e.g., using BN_dec2bn)
     BN_dec2bn(&a, "12345678901234567890");
  
     // Correct way to copy 'a' to 'b'
     BN_copy(b, a);
  
     // Alternatively, duplicate 'a' into a new BIGNUM 'c'
     BIGNUM *c = BN_dup(a);
     ```
   - **Converting BIGNUMs:**
     ```c
     // Convert a BIGNUM to its binary representation
     int len = BN_num_bytes(a);
     unsigned char *buf = malloc(len);
     if (buf == NULL) {
         // Handle error
     }
     BN_bn2bin(a, buf);
     
     // Convert from binary back to BIGNUM
     BIGNUM *from_bin = BN_bin2bn(buf, len, NULL);
     free(buf);
     ```
   - **Arithmetic Operations Example:**
     ```c
     BIGNUM *a = BN_new();
     BIGNUM *b = BN_new();
     BIGNUM *sum = BN_new();
  
     BN_dec2bn(&a, "12345678901234567890");
     BN_dec2bn(&b, "98765432109876543210");
  
     // Perform addition: sum = a + b
     BN_add(sum, a, b);
  
     // Convert the result to a decimal string for printing
     char *sum_str = BN_bn2dec(sum);
     printf("Sum: %s\n", sum_str);
  
     // Clean up
     OPENSSL_free(sum_str);
     BN_free(a);
     BN_free(b);
     BN_free(sum);
     ```

3. Testing:
   - Run your program to ensure that BIGNUMs are correctly created, copied, and converted.
   - Verify arithmetic operations (e.g., addition or modular exponentiation) produce the expected results.
   - Test edge cases such as handling very large numbers and ensuring proper memory management to avoid leaks.
   
## Resources

<!-- - [Course Slides on Cryptography Exercises]() -->
- [Official OpenSSL Documentation](https://www.openssl.org/docs/)
