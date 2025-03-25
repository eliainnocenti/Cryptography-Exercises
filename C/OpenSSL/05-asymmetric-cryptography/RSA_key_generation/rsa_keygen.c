#include <stdio.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Main function to generate an RSA key pair.
 * The private key is saved to "private.pem", and the public key is saved to "public.pem".
 */

int main() {
    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    RSA *rsa_keypair;
    BIGNUM *bne = BN_new();

    /* Initialize the BIGNUM structure with the RSA_F4 constant (65537) */
    if (!BN_set_word(bne, RSA_F4))
        handle_errors();

    /* Create a new RSA structure */
    rsa_keypair = RSA_new();

    /* Generate the RSA key pair with a key size of 2048 bits */
    if (!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();

    FILE *rsa_file;

    /* Save the private key to "private.pem" */
    if ((rsa_file = fopen("../private.pem", "w")) == NULL) {
        fprintf(stderr, "Error: Unable to open file for writing.\n");
        abort();
    }

    if (!PEM_write_RSAPrivateKey(rsa_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();
    fclose(rsa_file);

    /* Save the public key to "public.pem" */
    if ((rsa_file = fopen("../public.pem", "w")) == NULL) {
        fprintf(stderr, "Error: Unable to open file for writing.\n");
        abort();
    }

    if (!PEM_write_RSAPublicKey(rsa_file, rsa_keypair))
        handle_errors();
    fclose(rsa_file);

    /* Free the RSA structure and BIGNUM structure */
    RSA_free(rsa_keypair);
    BN_free(bne);

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
