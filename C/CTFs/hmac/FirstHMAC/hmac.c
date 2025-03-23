/* FirstHMAC */

/*
 * Write a program that computes the HMAC-SHA256 of two files whose names are passed as parameters 
 * from the command line (start from HMAC_computation_EVP).
 *
 * The flag is obtained as
 * 
 * CRYPTO25{hmac}
 * 
 * where hmac is obtained using the secret "keykeykeykeykeykey" and the two files attached 
 * to this challenge (and hexdigits in lowercase):
 * 
 * hmac = hex(HMAC-SHA256("keykeykeykeykeykey", file,file2))
 * 
 * where "keykeykeykeykeykey" is an ASCII string (no quotation marks)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#define MAX_BUFFER 1024

void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    /* Check if the correct number of arguments is provided */
    if (argc != 3) {
        fprintf(stderr, "Invalid parameters. Usage: %s <file1> <file2>\n", argv[0]);
        exit(1);
    }

    /* Open the first input file */
    FILE *f_in1;
    if ((f_in1 = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the input file: %s\n", argv[1]);
        exit(1);
    }

    /* Open the second input file */
    FILE *f_in2;
    if ((f_in2 = fopen(argv[2], "r")) == NULL) {
        fprintf(stderr, "Error opening the input file: %s\n", argv[2]);
        exit(1);
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Define the secret key */
    unsigned char key[] = "keykeykeykeykeykey"; // ASCII
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));

    /* Create a new HMAC context */
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new(); // Check for NULL

    /* Initialize the HMAC context with SHA256 */
    if (!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key))
        handle_errors();

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    /* Read and update the HMAC with the contents of the first file */
    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in1)) > 0) {
        if (!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    /* Read and update the HMAC with the contents of the second file */
    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in2)) > 0) {
        if (!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    /* Finalize the HMAC computation */
    unsigned char hmac_value[EVP_MAX_MD_SIZE]; // Use EVP_MAX_MD_SIZE for buffer size
    size_t hmac_len;

    if (!EVP_DigestSignFinal(hmac_ctx, NULL, &hmac_len)) // Get the length of the HMAC
        handle_errors();

    if (!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len)) // Get the HMAC value
        handle_errors();

    /* Free the HMAC context */
    EVP_MD_CTX_free(hmac_ctx);

    /* Print the HMAC in hexadecimal format */
    printf("The HMAC is: ");
    for (int i = 0; i < hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");

    /* Clean up */
    fclose(f_in1);
    fclose(f_in2);
    EVP_PKEY_free(hmac_key);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
