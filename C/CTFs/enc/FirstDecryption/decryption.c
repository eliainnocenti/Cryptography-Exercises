/* First Decryption */

/*
 * You detected the following message: jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==
 * which has been encrypted with the program whose code is attached (code.c).
 * 
 * It has been generated with the following command line string:
 * ./enc.exe file.txt 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 11111111111111112222222222222222 file.enc openssl base64 -in file.enc
 * 
 * Write a program in C that decrypts the content and get the flag!
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAX_BUFFER 1024

void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Decode a base64-encoded string into a malloc’d buffer.
 * The caller is responsible for freeing the returned buffer.
 * out_len is set to the number of decoded bytes.
 */
unsigned char *base64_decode(const char *input, int *out_len) {
    BIO *b64, *bmem;
    size_t input_len = strlen(input);

    /* Allocate a buffer large enough */
    unsigned char *buffer = malloc(input_len);
    if (!buffer) {
        perror("malloc");
        exit(1);
    }

    b64 = BIO_new(BIO_f_base64());

    /* Disable newlines in the base64 decoding */
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void*)input, input_len);
    bmem = BIO_push(b64, bmem);

    *out_len = BIO_read(bmem, buffer, input_len);
    BIO_free_all(bmem);

    return buffer;
}

int main(int argc, char **argv) {
    /* Load error strings for OpenSSL */
    ERR_load_crypto_strings();
    /* Load all OpenSSL algorithms */
    OpenSSL_add_all_algorithms();

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

    /* Read the base64-encoded ciphertext from the file */
    char b64_ciphertext[MAX_BUFFER];
    if (fgets(b64_ciphertext, MAX_BUFFER, f_in) == NULL) {
        fprintf(stderr, "Error reading the input file: %s\n", argv[1]);
        exit(1);
    }
    fclose(f_in);

    /* Decode the base64 ciphertext */
    int cipher_len;
    unsigned char *cipher_bytes = base64_decode(b64_ciphertext, &cipher_len);
    if (cipher_len <= 0) {
        fprintf(stderr, "Base64 decoding failed.\n");
        return 1;
    }

    /* Check if the key length is valid (64 characters for ChaCha20) */
    if (strlen(argv[2]) != 64) {
        fprintf(stderr, "Invalid key length. It must be 64 characters long.\n");
        return 1;
    }

    /* Convert the key from hexstring to byte array */
    unsigned char key[strlen(argv[2]) / 2];
    for (int i = 0; i < strlen(argv[2]) / 2; i++)
        sscanf(&argv[2][2 * i], "%2hhx", &key[i]);

    /* Check if the IV length is valid (32 characters for ChaCha20) */
    if (strlen(argv[3]) != 32) {
        fprintf(stderr, "Invalid iv length. It must be 32 characters long.\n");
        return 1;
    }

    /* Convert the IV from hexstring to byte array */
    unsigned char iv[strlen(argv[3]) / 2];
    for (int i = 0; i < strlen(argv[3]) / 2; i++)
        sscanf(&argv[3][2 * i], "%2hhx", &iv[i]);

    /* Create a new cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();

    /* Initialize the decryption operation */
    if (!EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT))
        handle_errors();

    unsigned char plaintext[MAX_BUFFER];
    int out_len1 = 0;
    if (!EVP_CipherUpdate(ctx, plaintext, &out_len1, cipher_bytes, cipher_len))
        handle_errors();

    int out_len2 = 0;
    if (!EVP_CipherFinal_ex(ctx, plaintext + out_len1, &out_len2))
        handle_errors();

    int total_len = out_len1 + out_len2;
    plaintext[total_len] = '\0'; // null-terminate the result

    printf("Decrypted text (flag): %s\n", plaintext);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    free(cipher_bytes);

    return 0;
}
