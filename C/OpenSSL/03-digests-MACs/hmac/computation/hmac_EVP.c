#include <stdio.h>
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

    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s <file>\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the input file: %s\n", argv[1]);
        exit(1);
    }

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    unsigned char key[] = "0123456789abcdef"; // ASCII
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));

    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new(); // Check for NULL

    if (!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha1(), NULL, hmac_key))
        handle_errors();

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in)) > 0) {
        if (!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    unsigned char hmac_value[EVP_MD_size(EVP_sha1())];
    size_t hmac_len;

    if (!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    EVP_MD_CTX_free(hmac_ctx);

    printf("The HMAC is: ");
    for (int i = 0; i < hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
