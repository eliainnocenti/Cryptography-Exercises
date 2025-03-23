/* Guess Algo */

/*
 * You sniffed the following Base64 string: ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=
 * 
 * You know it is an encrypted payload that has been ciphered with these parameters:
 * key = "0123456789ABCDEF" iv = "0123456789ABCDEF" (Note: key and iv are not to be taken as hex strings)
 * 
 * Write a program (based for instance on dec1.c or a modification of enc4.c) to decrypt it and obtain decryptedcontent.
 * 
 * Then, take note of the following instruction in your decryption program if(!EVP_CipherInit(ctx,algorithm_name(), key, iv, ENCRYPT))
 * 
 * When you succeed, build the flag in this way (Python-style string concatenation)
 * 
 * "CRYPTO25{" + decryptedcontent + algorithm_name + "}"
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define ENCRYPT 1
#define DECRYPT 0

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/* Function to decode a Base64 encoded string */
unsigned char *base64_decode(const char *base64data, int *len) {
    BIO *bio, *b64;
    int decodeLen = strlen(base64data);
    int padding = 0;

    /* Determine the amount of padding in the Base64 string */
    if (base64data[decodeLen-1] == '=' && base64data[decodeLen-2] == '=')
        padding = 2;
    else if (base64data[decodeLen-1] == '=')
        padding = 1;

    /* Calculate the length of the decoded data */
    int decodedLen = (decodeLen*3)/4 - padding;
    unsigned char *decodedData = (unsigned char *)malloc(decodedLen + 1);
    decodedData[decodedLen] = '\0';

    /* Create a BIO for Base64 decoding */
    bio = BIO_new_mem_buf(base64data, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not add newlines
    bio = BIO_push(b64, bio);

    /* Decode the Base64 data */
    *len = BIO_read(bio, decodedData, decodeLen);
    BIO_free_all(bio);

    return decodedData;
}

/* Function to decrypt the ciphertext using the specified algorithm */
int decrypt(const char *algorithm_name, unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    /* Create and initialize the cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    /* Get the cipher by name */
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm_name);
    if (!cipher) {
        fprintf(stderr, "Algorithm %s not found.\n", algorithm_name);
        return 0;
    }

    /* Initialize the decryption operation */
    if (!EVP_CipherInit(ctx, cipher, key, iv, DECRYPT)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len, plaintext_len = 0;

    /* Provide the ciphertext to be decrypted */
    if (!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    /* Finalize the decryption */
    if (!EVP_CipherFinal(ctx, plaintext + plaintext_len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* Null-terminate the plaintext */
    plaintext[plaintext_len] = '\0';

    return plaintext_len;
}

/* Function to check if the decrypted content is valid ASCII text */
int is_valid_ascii(unsigned char *plaintext, int len) {
    for (int i = 0; i < len; i++) {
        if (plaintext[i] < 32 || plaintext[i] > 126) {
            return 0;
        }
    }
    return 1;
}

int main() {
    /* Base64 encoded string */
    const char *base64_ciphertext = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";

    /* Key and IV (not hex strings) */
    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[] = "0123456789ABCDEF";

    /* Decode the Base64 encoded string */
    int ciphertext_len;
    unsigned char *ciphertext = base64_decode(base64_ciphertext, &ciphertext_len);

    /* Initialize OpenSSL algorithms and error strings */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* List of algorithms to try */
    const char *algorithms[] = {
        "aes-128-cbc", 
        "aes-192-cbc", 
        "aes-256-cbc",
        "des-cbc", 
        "des-ede3-cbc", 
        "bf-cbc",
        "cast5-cbc", 
        "rc2-cbc", 
        "rc4",
        "aria-128-cbc", 
        "aria-192-cbc", 
        "aria-256-cbc"
    };
    int num_algorithms = sizeof(algorithms) / sizeof(algorithms[0]);

    /* Buffer for the plaintext */
    unsigned char plaintext[ciphertext_len + EVP_MAX_BLOCK_LENGTH];

    /* Try each algorithm */
    for (int i = 0; i < num_algorithms; i++) {
        printf("Trying to decrypt with: %s\n", algorithms[i]);
        int plaintext_len = decrypt(algorithms[i], ciphertext, ciphertext_len, key, iv, plaintext);
        if (plaintext_len > 0 && is_valid_ascii(plaintext, plaintext_len)) {
            printf("- Decrypted content: %s\n", plaintext);
            printf("- Flag: CRYPTO25{%s%s}\n", plaintext, algorithms[i]);
        } else {
            printf("- Decryption failed or produced invalid ASCII text.\n");
        }
        printf("\n");
    }

    /* Clean up */
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    free(ciphertext);

    return 0;
}
