/* In the Name of the Cipher */

/*
 * Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.
 *
 * The input filename is passed as first parameter from the command line, key and IV are the second and third parameter,
 * the output file is the fourth parameter, the algorithm is the last parameter.
 * 
 * The algorithm name must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb). (In short, you have to extend enc4.c)
 * 
 * Look for the proper function here https://www.openssl.org/docs/man3.1/man3/EVP_EncryptInit.html
 * 
 * In doing the exercise you have found a very relevant function, build the flag as "CRYPTO25{" + relevantFunctionName + "}"
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAX_BUFFER 1024

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    /* Check if the correct number of arguments is provided */
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <input file> <key> <iv> <output file> <algorithm>\n", argv[0]);
        exit(1);
    }

    /* Open the input file for reading */
    FILE *f_in = fopen(argv[1], "rb");
    if (!f_in) {
        perror("Error opening input file");
        exit(1);
    }

    /* Open the output file for writing */
    FILE *f_out = fopen(argv[4], "wb");
    if (!f_out) {
        perror("Error opening output file");
        fclose(f_in);
        exit(1);
    }

    /* Convert the key from hexstring to byte array */
    unsigned char key[strlen(argv[2])/2];
    for (int i = 0; i < strlen(argv[2])/2; i++)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);

    /* Convert the IV from hexstring to byte array */
    unsigned char iv[strlen(argv[3])/2];
    for (int i = 0; i < strlen(argv[3])/2; i++)
        sscanf(&argv[3][2*i], "%2hhx", &iv[i]);

    /* Initialize OpenSSL algorithms and error strings */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Get the cipher by name */
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(argv[5]);
    if (!cipher) {
        fprintf(stderr, "Unknown cipher %s\n", argv[5]);
        fclose(f_in);
        fclose(f_out);
        exit(1);
    }

    /* Create and initialize the cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    /* Initialize the encryption operation */
    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        handle_errors();

    unsigned char buffer[MAX_BUFFER];
    unsigned char ciphertext[MAX_BUFFER + EVP_CIPHER_block_size(cipher)];
    int len, ciphertext_len = 0;

    /* Read the input file and encrypt its content */
    while (1) {
        int n_read = fread(buffer, 1, MAX_BUFFER, f_in);
        if (n_read <= 0) break;

        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, n_read))
            handle_errors();
        fwrite(ciphertext, 1, len, f_out);
        ciphertext_len += len;
    }

    /* Finalize the encryption */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len))
        handle_errors();
    fwrite(ciphertext, 1, len, f_out);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    fclose(f_in);
    fclose(f_out);

    /* Cleanup OpenSSL */
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    /* Print the size of the ciphertext and the flag */
    printf("Size of the ciphertext: %d\n", ciphertext_len);
    printf("Flag: CRYPTO25{EVP_get_cipherbyname}\n");

    return 0;
}
