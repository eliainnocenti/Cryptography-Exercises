# Asymmetric Cryptography CTF Challenges

This directory contains Capture The Flag (CTF) challenges focused on asymmetric cryptography, primarily RSA and related public-key cryptosystems. These challenges cover various attack scenarios, implementation flaws, and cryptanalysis techniques used in real-world penetration testing and cryptographic research.

## Challenges Overview

### [Inferious-prime-(CryptoHack)](./Inferious-prime-(CryptoHack)/)
A challenge from CryptoHack focusing on prime number vulnerabilities in RSA implementations. This typically involves weak prime generation or factorization attacks.

**Key Concepts:**
- Prime number generation
- Factorization attacks
- RSA key analysis

### RSA Progressive Challenges (Levels 1-9)

A series of progressively difficult RSA challenges, each building upon the previous level's complexity:

#### [RSA-Level-1](./RSA-Level-1/)
Introduction to basic RSA vulnerabilities and simple attacks.

#### [RSA-Level-2](./RSA-Level-2/)
Intermediate RSA challenges involving parameter manipulation.

#### [RSA-Level-3](./RSA-Level-3/)
Advanced RSA scenarios with more complex attack vectors.

#### [RSA-Level-4](./RSA-Level-4/)
Multi-parameter RSA attacks and cryptanalysis.

#### [RSA-Level-5](./RSA-Level-5/)
Complex RSA implementations with multiple vulnerabilities.

#### [RSA-Level-6](./RSA-Level-6/)
Advanced factorization and mathematical attacks on RSA.

#### [RSA-Level-7](./RSA-Level-7/)
Sophisticated RSA cryptanalysis requiring multiple attack techniques.

#### [RSA-Level-8](./RSA-Level-8/)
Expert-level RSA challenges with real-world complexity.

#### [RSA-Level-9](./RSA-Level-9/)
Master-level RSA attacks combining multiple advanced techniques.

## Common Attack Categories

### Mathematical Attacks
- **Small e attacks:** Exploiting small public exponents
- **Common modulus attacks:** Multiple users sharing the same modulus
- **Low private exponent attacks:** Wiener's attack and variants
- **Factorization methods:** Pollard's rho, quadratic sieve, etc.

### Implementation Attacks
- **Timing attacks:** Exploiting timing differences in RSA operations
- **Padding oracle attacks:** PKCS#1 v1.5 padding vulnerabilities
- **Fault injection:** Inducing computational errors to reveal secrets
- **Power analysis:** Side-channel attacks on hardware implementations

### Parameter-Based Attacks
- **Weak prime generation:** Predictable or factorable primes
- **Related key attacks:** Exploiting relationships between multiple keys
- **Broadcast attacks:** Same message encrypted with multiple keys
- **Chosen ciphertext attacks:** Manipulating ciphertexts to extract information

## Tools and Libraries

Essential tools for these challenges:
- `pycryptodome` - Comprehensive cryptographic library
- `gmpy2` - High-performance multiple-precision arithmetic
- `sage` - Mathematical software for advanced computations
- `factordb` - Online factorization database
- `RsaCtfTool` - Automated RSA attack toolkit
- Custom implementations for specific attack scenarios

## Mathematical Background

Key mathematical concepts required:
- **Modular arithmetic:** Operations in finite fields
- **Prime factorization:** Algorithms and complexity
- **Euler's totient function:** φ(n) and its properties
- **Chinese Remainder Theorem:** Efficient computation techniques
- **Continued fractions:** Used in cryptanalytic attacks
- **Lattice reduction:** Advanced mathematical attack methods
