#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    /* Load error strings for OpenSSL */
    ERR_load_crypto_strings();
    /* Load all OpenSSL algorithms */
    OpenSSL_add_all_algorithms();

    /* Create a new cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Check for NULL

    /* Define the key and IV (Initialization Vector) */
    unsigned char key[] = "1234567890abcdef"; // ASCII
    unsigned char iv[] = "1234567890abcdef";  // ASCII

    /* Define the ciphertext to be decrypted (hex string) */
    unsigned char ciphertext[] = "a54c303f7c85b6a753a2c02e0e1aabcf0d9e8db1b553c1aad313897655974849cf37e72b83d0b9d68471787f61cf7e7c5728edd2c0803c5da46a5bd77e111fb6"; // 96 bytes long

    /* Initialize the decryption operation */
    if (!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT))
        handle_errors();

    /* Allocate memory for the plaintext and binary ciphertext */
    unsigned char plaintext[strlen(ciphertext)/2];
    unsigned char ciphertext_binary[strlen(ciphertext)/2];

    /* Convert the ciphertext from hex string to binary */
    for (int i = 0; i < strlen(ciphertext)/2; i++)
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_binary[i]);

    int len = 0; // Temporary output of the Update function
    int plaintext_len = 0;

    /* Decrypt the ciphertext */
    if (!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext_binary, strlen(ciphertext)/2))
        handle_errors();

    printf("After update: %d\n", len);
    plaintext_len += len;

    /* Finalize the decryption */
    if (!EVP_CipherFinal(ctx, plaintext + plaintext_len, &len))
        handle_errors();

    printf("After final: %d\n", len);
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    /* Null-terminate the plaintext and print it */
    plaintext[plaintext_len] = '\0';
    printf("Plaintext: %s\n", plaintext);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
