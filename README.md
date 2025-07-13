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

- **Python for Cryptography and Attacks:**  
  Focus on rapid prototyping, cryptanalysis, and CTF-style challenges. Python is used for both implementing cryptographic primitives and attacking them, making it ideal for practical exploit development and cryptanalysis.

> [!NOTE]
> For further details, refer to the course slides and materials provided during the lectures.

## Repository Structure

The repository is organized as follows:

| Section         | Description                                                            |
| --------------- | ---------------------------------------------------------------------- |
| **`C/OpenSSL`** | Exercises using C and OpenSSL covering various cryptographic topics.   |
| **`C/CTFs`**    | Capture The Flag (CTF) challenges implemented in C, focusing on practical cryptographic problems and solutions. |
| **`Python`**    | Python-based cryptography exercises, attacks, and CTF challenges.      |

### C/OpenSSL

Inside the **`C/OpenSSL`** folder, exercises are structured into dedicated directories:

| Exercise                                                                        | Description                                                              |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| [**`Random Numbers`**](C/OpenSSL/01-random-numbers/README.md)                   | Generating cryptographically secure pseudo-random numbers using OpenSSL. |
| [**`Symmetric Encryption`**](C/OpenSSL/02-symmetric-encryption/README.md)       | Implementing symmetric encryption algorithms with OpenSSL.               |
| [**`Digests and MACs`**](C/OpenSSL/03-digests-MACs/README.md)                   | Exploring cryptographic digests and MACs.                                |
| [**`Big Numbers`**](C/OpenSSL/04-big-numbers/README.md)                         | Handling big numbers in cryptographic operations.                        |
| [**`Asymmetric Cryptography`**](C/OpenSSL/05-asymmetric-cryptography/README.md) | Working with asymmetric cryptography and public key operations.          |

### C/CTFs

Inside the **`C/CTFs`** folder, exercises are structured into dedicated directories:

| CTF Challenge                                                                 | Description                                                              |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| [**`Rand`**](C/CTFs/rand/README.md)                                           | Bytewise operations on random strings to capture the flag.               |
| [**`Encryption`**](C/CTFs/enc/README.md)                                      | Various encryption challenges including padding, decryption, and more.   |
| [**`Digest`**](C/CTFs/dgst/README.md)                                         | Compute keyed digests and modify digest algorithms to capture the flag.  |
| [**`HMAC`**](C/CTFs/hmac/README.md)                                           | Compute HMAC-SHA256 of two files to capture the flag.                    |
| [**`Asymmetric`**](C/CTFs/asym/README.md)                                     | Find missing parameters using BIGNUM primitives to capture the flag.     |

### Python

The **`Python/`** directory has been significantly expanded and now includes a wide range of cryptography exercises, attacks, and CTF-style challenges. The structure is as follows:

#### Basics

The Basics section provides comprehensive implementations of fundamental cryptographic concepts:

| Exercise/Subdirectory                                                | Description                                                                                    |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [**`symmetric/`**](Python/Basics/symmetric/README.md)              | Symmetric cryptography fundamentals: key generation, block/stream ciphers, padding, AEAD, hash functions, and key derivation. |
| [**`asymmetric/`**](Python/Basics/asymmetric/README.md)            | Asymmetric cryptography fundamentals: prime generation, RSA operations, digital signatures, and key exchange protocols. |

#### Attacks

The Attacks section contains practical implementations of cryptographic attack techniques:

| Exercise/Subdirectory   | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| **`symmetric/`**        | Attacks on symmetric cryptography: ECB/CBC attacks, padding oracle attacks, keystream reuse, and cipher vulnerabilities. |
| **`asymmetric/`**       | Attacks on asymmetric cryptography: RSA vulnerabilities, factorization attacks, side-channel analysis, and mathematical cryptanalysis. |

#### CTFs

The CTF section contains practical challenge scenarios designed to test and improve cryptographic attack skills:

| Exercise/Subdirectory                                               | Description                                                                                                      |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [**`symmetric/`**](Python/CTFs/symmetric/README.md)               | CTF challenges focused on symmetric cryptography attacks: padding oracles, mode vulnerabilities, cookie forgery, and implementation flaws. |
| [**`asymmetric/`**](Python/CTFs/asymmetric/README.md)             | Progressive RSA challenges (Levels 1-9) and public-key cryptosystem attacks, covering factorization, parameter attacks, and advanced cryptanalysis. |
| [**`hash/`**](Python/CTFs/hash/README.md)                         | Hash function challenges including collision attacks, length extension vulnerabilities, and cryptographic hash analysis. |

## Author

- GitHub: [@eliainnocenti](https://github.com/eliainnocenti)
- Email: [elia.innocenti@studenti.polito.it](mailto:elia.innocenti@studenti.polito.it)
