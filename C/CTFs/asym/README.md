## Asymmetric Encryption CTFs

### "guess what" CTF

#### Challenge Description
Find the missing parameter using BIGNUM primitives.

#### Key Instructions
1. Convert the given hex strings to BIGNUMs.
2. Perform BIGNUM operations to find the missing parameter.
3. Print the result as a colon-separated hex string surrounded by `CRYPTO25{}`.

#### Example Code
Refer to the [asym.c](./guess-what/asym.c) file for the implementation details.

#### Additional Resources
- [OpenSSL BIGNUM Documentation](https://www.openssl.org/docs/man1.1.1/man3/BN_bn2hex.html)
- [Asymmetric Cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography)
