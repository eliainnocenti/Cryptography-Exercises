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
 * Main function to generate a digital signature for a file.
 * argv[1]: Path to the file to be signed.
 * argv[2]: Path to the file containing the private key.
 */

int main(int argc, char **argv) {
    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Check if the correct number of arguments is provided */
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file to sign> <private key file>\n", argv[0]);
        return 1;
    }

    /* Open the file to be signed for reading */
    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open file for reading.\n");
        return 1;
    }

    /* Open the private key file for reading */
    FILE *f_key;
    if ((f_key = fopen(argv[2], "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open private key file.\n");
        return 1;
    }

    /* Read the private key from the PEM file */
    EVP_PKEY *private_key = PEM_read_PrivateKey(f_key, NULL, NULL, NULL);
    if (private_key == NULL)
        handle_errors();
    fclose(f_key);

    /* Create a new EVP_MD_CTX structure for signing */
    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    if (sign_ctx == NULL)
        handle_errors();

    /* Initialize the signing context with the private key and SHA-256 algorithm */
    if (!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, private_key))
        handle_errors();

    /* Read the file to be signed in chunks and update the signing context */
    unsigned char buffer[MAX_BUFFER];
    size_t n_read;
    while ((n_read = fread(buffer, 1, MAX_BUFFER, f_in)) > 0) {
        if (!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }
    fclose(f_in);

    /* Determine the size of the signature */
    unsigned char signature[EVP_PKEY_size(private_key)];
    size_t signature_len;
    size_t digest_len;

    /* Finalize the signing process to calculate the signature length */
    if (!EVP_DigestSignFinal(sign_ctx, NULL, &digest_len))
        handle_errors();

    /* Generate the signature */
    if (!EVP_DigestSignFinal(sign_ctx, signature, &signature_len))
        handle_errors();

    /* Clean up the signing context */
    EVP_MD_CTX_free(sign_ctx);

    /* Write the signature to a file named "signature.bin" */
    FILE *f_out;
    if ((f_out = fopen("signature.bin", "w")) == NULL) {
        fprintf(stderr, "Error: Unable to open file for writing.\n");
        return 1;
    }

    /* Write the signature to the file */
    if (fwrite(signature, 1, signature_len, f_out) < signature_len) {
        fprintf(stderr, "Error: Unable to write to file.\n");
        return 1;
    }
    fclose(f_out);

    printf("Signature written to signature.bin\n");

    /* Free the private key */
    EVP_PKEY_free(private_key);

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
