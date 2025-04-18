#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAXSIZE 1024

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * argv[1] --> input file
 * argv[2] --> key (hexstring)
 * argv[3] --> iv (hexstring)
 * save in a buffer in memory the result of the encryption
 */

int main(int argc, char **argv) {
    /* Load error strings for OpenSSL */
    ERR_load_crypto_strings();
    /* Load all OpenSSL algorithms */
    OpenSSL_add_all_algorithms();

    /* Create a new cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Check for NULL

    /* Check if the correct number of arguments is provided */
    if (argc != 4) {
        fprintf(stderr, "Invalid parameters. Usage: %s <input file> <key> <iv>\n", argv[0]);
        exit(1);
    }

    /* Open the input file for reading */
    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the input file: %s\n", argv[1]);
        exit(1);
    }

    /* Check if the key length is valid (32 characters for AES-128) */
    if (strlen(argv[2]) != 32) {
        fprintf(stderr, "Invalid key length. It must be 32 characters long.\n");
        exit(1);
    }

    /* Convert the key from hexstring to byte array */
    unsigned char key[strlen(argv[2])/2];
    for (int i = 0; i < strlen(argv[2])/2; i++)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);

    /* Check if the IV length is valid (32 characters for AES-128) */
    if (strlen(argv[3]) != 32) {
        fprintf(stderr, "Invalid iv length. It must be 32 characters long.\n");
        exit(1);
    }
    
    /* Convert the IV from hexstring to byte array */
    unsigned char iv[strlen(argv[3])/2];
    for (int i = 0; i < strlen(argv[3])/2; i++)
        sscanf(&argv[3][2*i], "%2hhx", &iv[i]);

    /* Initialize the encryption operation */
    if (!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXSIZE];
    unsigned char ciphertext[100 * MAXSIZE];

    int len, ciphertext_len = 0;

    /* Read the input file and encrypt its content */
    while ((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0) {
        /* Check if the ciphertext buffer is large enough */
        if (ciphertext_len > 100 * MAXSIZE - n_read - EVP_CIPHER_CTX_block_size(ctx)) {
            fprintf(stderr, "The ciphertext buffer is too small.\n");
            exit(1);
        }

        if (!EVP_CipherUpdate(ctx, ciphertext + ciphertext_len, &len, buffer, n_read))
            handle_errors();
        ciphertext_len += len;
    }

    /* Finalize the encryption */
    if (!EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &len))
        handle_errors();
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

    fclose(f_in);

    return 0;
}
