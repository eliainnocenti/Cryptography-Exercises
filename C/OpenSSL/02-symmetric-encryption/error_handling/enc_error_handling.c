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

    /* Initialize the encryption operation */
    if (!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    /* Define the plaintext to be encrypted */
    unsigned char plaintext[] = "This variable contains the data to be encrypted."; // 48 bytes long
    unsigned char ciphertext[48]; // 48 bytes long

    int len = 0; // Temporary output of the Update function
    int ciphertext_len = 0;

    /* Encrypt the plaintext */
    if (!EVP_CipherUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext)))
        handle_errors();

    printf("After update: %d\n", len);
    ciphertext_len += len;

    /* Finalize the encryption */
    if (!EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &len))
        handle_errors();

    printf("After final: %d\n", len);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    printf("Size of the ciphertext: %d\n", ciphertext_len);

    /* Print the ciphertext in hex format */
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
