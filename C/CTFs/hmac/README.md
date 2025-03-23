## HMAC CTFs

### "FirstHMAC" CTF

#### Challenge Description
In this challenge, you need to compute the HMAC-SHA256 of two files whose names are passed as parameters from the command line. The flag is obtained using the secret "keykeykeykeykeykey" and the two files attached to this challenge.

#### Key Instructions
1. Read the contents of the two input files.
2. Use the secret key "keykeykeykeykeykey" to compute the HMAC-SHA256 of the concatenated contents of the two files.
3. Print the HMAC in hexadecimal format.
4. Surround the HMAC with `CRYPTO25{}` to obtain the flag.

#### Example Code
Refer to the [hmac.c](./FirstHMAC/hmac.c) file for the implementation details.

#### Additional Resources
- [OpenSSL HMAC Documentation](https://www.openssl.org/docs/man1.1.1/man3/HMAC.html)
- [HMAC-SHA256](https://en.wikipedia.org/wiki/HMAC)
