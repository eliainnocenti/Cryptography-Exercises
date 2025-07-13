# Hash Function CTF Challenges

This directory contains Capture The Flag (CTF) challenges focused on hash functions, their vulnerabilities, and related cryptographic attacks. These challenges cover various hash-based exploits and cryptanalysis techniques.

## Challenges Overview

### [Equality](./Equality/)
A challenge exploring hash collision scenarios and equality testing vulnerabilities. This exercise demonstrates how hash collisions can be exploited in authentication or integrity checking systems.

**Key Concepts:**
- Hash collisions
- Equality testing vulnerabilities
- Hash function properties

### [HA-SHop](./HA-SHop/)
A hash-based challenge involving SHA hash functions and their cryptographic properties. This challenge typically involves length extension attacks or other SHA-specific vulnerabilities.

**Key Concepts:**
- SHA hash functions
- Length extension attacks
- Hash function cryptanalysis
- Message authentication bypasses

## Common Attack Patterns

- **Hash Collisions:** Finding two different inputs that produce the same hash output
- **Length Extension:** Exploiting the Merkle-Damgård construction to append data without knowing the original message
- **Preimage Attacks:** Finding an input that produces a specific hash output
- **Birthday Attacks:** Exploiting the birthday paradox to find collisions more efficiently

## Tools and Libraries

Common tools used in these challenges:
- `hashlib` - Python's built-in hash library
- `pwntools` - CTF toolkit for exploit development
- Custom hash implementations for analysis
- Online hash databases and collision generators
