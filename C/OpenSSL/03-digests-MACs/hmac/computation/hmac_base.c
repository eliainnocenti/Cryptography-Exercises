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

    HMAC_CTX *hmac_ctx = HMAC_CTX_new(); // Check for NULL

    if (!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha1(), NULL))
        handle_errors();

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in)) > 0) {
        if (!HMAC_Update(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    unsigned char hmac_value[HMAC_size(hmac_ctx)];
    int hmac_len;

    if (!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    HMAC_CTX_free(hmac_ctx);

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
