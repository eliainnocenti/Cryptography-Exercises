## Digest CTFs

### "ChangeDGST" CTF

#### Challenge Description
Modify the code to compute the SHA256 hash.

#### Key Instructions
1. Change the digest algorithm to SHA256.
2. Compute the SHA256 hash of the modified file.
3. Print the hash as a hex string surrounded by `CRYPTO25{}`.

#### Example Code
Refer to the [hash.c](./ChangeDGST/hash.c) file for the implementation details.

### "Keyed Digest" CTF

#### Challenge Description
Compute the keyed digest using SHA512.

#### Key Instructions
1. Concatenate the secret, input file content, and secret.
2. Compute the SHA512 digest of the concatenated data.
3. Print the digest as a hex string surrounded by `CRYPTO25{}`.

#### Example Code
Refer to the [hash.c](./Keyed-digest/hash.c) file for the implementation details.

#### Additional Resources
- [OpenSSL Digest Documentation](https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestInit.html)
- [SHA-256](https://en.wikipedia.org/wiki/SHA-2)
- [SHA-512](https://en.wikipedia.org/wiki/SHA-2)
