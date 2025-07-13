# Symmetric Cryptography CTF Challenges

This directory contains Capture The Flag (CTF) challenges focused on symmetric cryptography attacks, including block cipher vulnerabilities, stream cipher weaknesses, and implementation flaws. These challenges cover practical attack scenarios commonly encountered in penetration testing and cryptographic research.

## Challenges Overview

### Time-Based Attacks
#### [Back-to-the-future](./Back-to-the-future/)
A challenge involving time-based cryptographic vulnerabilities, possibly exploiting timestamp-based encryption or time-travel scenarios in cryptographic protocols.

#### [decrypt-it-if-you-are-fast-enough!](./decrypt-it-if-you-are-fast-enough!/)
A time-sensitive decryption challenge that requires quick analysis and exploitation of cryptographic weaknesses.

### Decryption Challenges
#### [decrypt-the-flag!](./decrypt-the-flag!/)
A straightforward decryption challenge focusing on breaking symmetric encryption to recover the flag.

#### [force-decryption](./force-decryption/)
A brute-force or exhaustive search challenge requiring systematic key recovery techniques.

### Mode-Guessing Challenges
#### [guess-mode-one-shot](./guess-mode-one-shot/)
A challenge requiring identification and exploitation of the encryption mode in a single attempt.

#### [guess-mode-double-shot](./guess-mode-double-shot/)
An advanced mode-guessing challenge with multiple opportunities but increased complexity.

### Oracle Attacks
#### [Fool-the-Oracle](./Fool-the-Oracle/)
Introduction to padding oracle attacks and related cryptographic oracle vulnerabilities.

#### [Fool-the-Oracle-v2](./Fool-the-Oracle-v2/)
Advanced padding oracle scenarios with additional protections to bypass.

#### [Fool-the-Oracle-v3](./Fool-the-Oracle-v3/)
Expert-level oracle attacks requiring sophisticated techniques and multiple attack vectors.

#### [Fool-the-Oracle-v4](./Fool-the-Oracle-v4/)
Master-level oracle challenges combining multiple advanced cryptographic attack methods.

### Cookie and Session Attacks
#### [forge-a-cookie](./forge-a-cookie/)
Web security challenge involving cryptographic cookie forgery and session manipulation.

#### [forge-another-cookie](./forge-another-cookie/)
Advanced cookie forgery with additional security mechanisms to bypass.

#### [Forge-another-JSON-cookie](./Forge-another-JSON-cookie/)
JSON-based cookie forgery challenge involving structured data manipulation and cryptographic attacks.

### File-Based Challenges
#### [long-file](./long-file/)
Challenge involving encryption/decryption of large files, possibly exploiting block cipher properties or implementation flaws.

#### [long-secret-message](./long-secret-message/)
Extended message decryption challenge requiring analysis of long ciphertexts and pattern recognition.

### Educational Examples
#### [Examples-Pwntools](./Examples-Pwntools/)
Educational examples demonstrating the use of pwntools for cryptographic exploitation and CTF problem solving.

## Common Attack Categories

### Block Cipher Attacks
- **ECB Mode Attacks:** Pattern analysis and block manipulation
- **CBC Bit-Flipping:** Controlled ciphertext modification
- **Padding Oracle Attacks:** PKCS#7 padding vulnerabilities
- **Meet-in-the-Middle:** Attacks on double encryption

### Stream Cipher Attacks
- **Keystream Reuse:** Many-time pad attacks
- **Nonce Reuse:** IV/nonce collision exploitation
- **Related-Key Attacks:** Exploiting key relationships
- **Differential Cryptanalysis:** Statistical attack methods

### Oracle Attacks
- **Padding Oracles:** Error-based information leakage
- **Timing Oracles:** Exploiting timing differences
- **Error Oracles:** Using error messages for cryptanalysis
- **Length Oracles:** Information from ciphertext length

### Web Security Attacks
- **Session Token Forgery:** Creating valid authentication tokens
- **Cookie Manipulation:** Bypassing authentication through cookie modification
- **JSON Web Token (JWT) Attacks:** Exploiting JWT implementation flaws
- **CSRF Token Bypass:** Cross-site request forgery through cryptographic weaknesses

## Tools and Libraries

Essential tools for these challenges:
- `pwntools` - CTF exploitation framework
- `pycryptodome` - Comprehensive cryptographic library
- `requests` - HTTP library for web-based challenges
- `binascii` - Binary data manipulation
- Custom oracle interaction scripts
- Automated attack tools and frameworks

## Attack Methodologies

### Systematic Approach
1. **Reconnaissance:** Identify the cryptographic system and parameters
2. **Vulnerability Assessment:** Analyze potential weaknesses and attack vectors
3. **Exploitation:** Implement and execute the appropriate attack
4. **Verification:** Confirm successful attack and flag recovery

### Common Techniques
- **Chosen Plaintext Attacks:** Controlling input to analyze output patterns
- **Chosen Ciphertext Attacks:** Manipulating ciphertexts to extract information
- **Known Plaintext Attacks:** Leveraging known plaintext-ciphertext pairs
- **Ciphertext-Only Attacks:** Extracting information from ciphertext alone
