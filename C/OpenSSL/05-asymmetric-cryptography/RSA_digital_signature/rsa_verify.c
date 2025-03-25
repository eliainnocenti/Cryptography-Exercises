#include <stdio.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define MAX_BUFFER 1024

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Main function to verify a digital signature.
 * argv[1]: Path to the file containing the original data.
 * argv[2]: Path to the file containing the digital signature.
 * argv[3]: Path to the file containing the public key.
 */

int main(int argc, char **argv) {
    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Check if the correct number of arguments is provided */
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <original file> <signature file> <public key file>\n", argv[0]);
        return 1;
    }

    /* Open the original data file for reading */
    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open original file for reading.\n");
        return 1;
    }

    /* Open the signature file for reading */
    FILE *f_sig;
    if ((f_sig = fopen(argv[2], "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open signature file for reading.\n");
        return 1;
    }

    /* Open the public key file for reading */
    FILE *f_key;
    if ((f_key = fopen(argv[3], "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open public key file.\n");
        return 1;
    }

    /* Read the public key from the PEM file */
    EVP_PKEY *public_key = PEM_read_PUBKEY(f_key, NULL, NULL, NULL);
    if (public_key == NULL)
        handle_errors();
    fclose(f_key);

    /* Create a new EVP_MD_CTX structure for verification */
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new();
    if (verify_ctx == NULL)
        handle_errors();

    /* Initialize the verification context with the public key and SHA-256 algorithm */
    if (!EVP_DigestVerifyInit(verify_ctx, NULL, EVP_sha256(), NULL, public_key))
        handle_errors();

    /* Read the original data in chunks and update the verification context */
    unsigned char buffer[MAX_BUFFER];
    size_t n_read;
    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in)) > 0) {
        if (!EVP_DigestVerifyUpdate(verify_ctx, buffer, n_read))
            handle_errors();
    }
    fclose(f_in);

    /* Determine the size of the signature file */
    fseek(f_sig, 0, SEEK_END);
    size_t sig_len = ftell(f_sig);
    fseek(f_sig, 0, SEEK_SET);

    /* Allocate memory to store the signature */
    unsigned char *signature = malloc(sig_len);
    if (signature == NULL) {
        fprintf(stderr, "Error: Unable to allocate memory for signature.\n");
        return 1;
    }

    /* Read the signature from the file */
    if (fread(signature, 1, sig_len, f_sig) < sig_len) {
        fprintf(stderr, "Error: Unable to read signature file.\n");
        free(signature);
        return 1;
    }
    fclose(f_sig);

    /* Verify the signature using the verification context */
    int verify_result = EVP_DigestVerifyFinal(verify_ctx, signature, sig_len);
    free(signature);

    /* Clean up the verification context and public key */
    EVP_MD_CTX_free(verify_ctx);
    EVP_PKEY_free(public_key);

    /* Print the result of the verification */
    if (verify_result == 1) {
        printf("Signature is valid.\n");
    } else if (verify_result == 0) {
        printf("Signature is invalid.\n");
    } else {
        handle_errors();
    }

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
