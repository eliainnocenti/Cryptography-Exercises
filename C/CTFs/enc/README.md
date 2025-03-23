## Encryption CTFs

### "Padding" CTF

#### Challenge Description
Disable the padding in the encryption process.

#### Key Instructions
1. Use the `EVP_CIPHER_CTX_set_padding(ctx, 0);` function to disable padding.
2. Surround the instruction with `CRYPTO25{}` to obtain the flag.

#### Example Code
Refer to the [enc1.c](./Padding/enc1.c) file for the implementation details.

### "First Decryption" CTF

#### Challenge Description
Decrypt a Base64 encoded message using the specified key and IV.

#### Key Instructions
1. Decode the Base64 encoded message.
2. Use the `EVP_CipherInit` function to initialize the decryption operation.
3. Decrypt the ciphertext and print the decrypted text as the flag.

#### Example Code
Refer to the [decryption.c](./FirstDecryption/decryption.c) file for the implementation details.

### "In the Name of the Cipher" CTF

#### Challenge Description
Encrypt the content of a file using a user-selected algorithm.

#### Key Instructions
1. Read the input file, key, IV, output file, and algorithm from the command line.
2. Use the `EVP_get_cipherbyname` function to get the cipher by name.
3. Encrypt the file content using the specified algorithm.
4. Print the flag as `CRYPTO25{EVP_get_cipherbyname}`.

#### Example Code
Refer to the [encryption.c](./In-the-Name-of-the-Cipher/encryption.c) file for the implementation details.

### "Guess Algo" CTF

#### Challenge Description
Decrypt a Base64 encoded string using the specified key and IV.

#### Key Instructions
1. Decode the Base64 encoded string.
2. Try different algorithms to decrypt the ciphertext.
3. Check if the decrypted content is valid ASCII text.
4. Print the flag as `CRYPTO25{decryptedcontentalgorithm_name}`.

#### Example Code
Refer to the [decryption.c](./Guess-Algo/decryption.c) file for the implementation details.

#### Additional Resources
- [OpenSSL Encryption Documentation](https://www.openssl.org/docs/man1.1.1/man3/EVP_EncryptInit.html)
- [Base64 Encoding](https://en.wikipedia.org/wiki/Base64)
