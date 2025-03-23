# Cryptography Exercises

![polito](resources/logo_polito.jpg)

This repository contains materials for the **Cryptography** course at **Politecnico di Torino**, focusing on both implementation and attack scenarios to bridge theory and practice.

## Overview

The exercises are divided into two main parts:

- **C Programming with OpenSSL:**  
  Learn how to implement cryptographic primitives and protocols in C. Exercises include:

  - **Random Numbers:** Generating cryptographically secure pseudo-random numbers.
  - **Symmetric Encryption:** Implementing and understanding symmetric ciphers.
  - **Digests & MACs:** Working with hash functions and message authentication codes.
  - **Big Numbers:** Handling large integer arithmetic for crypto applications.
  - **Asymmetric Cryptography:** Exploring public-key techniques and RSA.

- **Python for Cryptography Attacks:**  
  Focus on rapidly prototyping and executing attacks, as Python is the de facto language for quick and effective exploit development.

> [!NOTE]
> For further details, refer to the course slides and materials provided during the lectures.

## Repository Structure

The repository is organized as follows:

| Section         | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| **`C/OpenSSL`** | Exercises using C and OpenSSL covering various cryptographic topics.   |
| **`C/CTFs`**    | Capture The Flag (CTF) challenges implemented in C, focusing on practical cryptographic problems and solutions. |
| **`Python`**    | Placeholder for cryptography and CTF challenges implemented in Python. |

Inside the **`C/OpenSSL`** folder, exercises are structured into dedicated directories:

| Exercise                                                                        | Description                                                              |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| [**`Random Numbers`**](C/OpenSSL/01-random-numbers/README.md)                   | Generating cryptographically secure pseudo-random numbers using OpenSSL. |
| [**`Symmetric Encryption`**](C/OpenSSL/02-symmetric-encryption/README.md)       | Implementing symmetric encryption algorithms with OpenSSL.               |
| [**`Digests and MACs`**](C/OpenSSL/03-digests-MACs/README.md)                   | Exploring cryptographic digests and MACs.                                |
| [**`Big Numbers`**](C/OpenSSL/04-big-numbers/README.md)                         | Handling big numbers in cryptographic operations.                        |
| [**`Asymmetric Cryptography`**](C/OpenSSL/05-asymmetric-cryptography/README.md) | Working with asymmetric cryptography and public key operations.          |

Inside the **`C/CTFs`** folder, exercises are structured into dedicated directories:

| CTF Challenge                                                                 | Description                                                              |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| [**`Rand`**](C/CTFs/rand/README.md)                                           | Bytewise operations on random strings to capture the flag.               |
| [**`Encryption`**](C/CTFs/enc/README.md)                                      | Various encryption challenges including padding, decryption, and more.   |
| [**`Digest`**](C/CTFs/dgst/README.md)                                         | Compute keyed digests and modify digest algorithms to capture the flag.  |
| [**`HMAC`**](C/CTFs/hmac/README.md)                                           | Compute HMAC-SHA256 of two files to capture the flag.                    |
| [**`Asymmetric`**](C/CTFs/asym/README.md)                                     | Find missing parameters using BIGNUM primitives to capture the flag.     |

<!-- ## Resources

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Python Cryptography Library](https://cryptography.io/)
- [CryptoCTF Challenges](https://cryptoctf.m0lecon.it/)
- [Course GitHub Repository](https://github.com/aldobas/cryptography-03lpyov-exercises) -->

## Author

- GitHub: [@eliainnocenti](https://github.com/eliainnocenti)
- Email: [elia.innocenti@studenti.polito.it](mailto:elia.innocenti@studenti.polito.it)
