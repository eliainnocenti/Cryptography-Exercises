#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

/*
 * Main function to encrypt a message using a public RSA key.
 * The public key is loaded from a PEM file, and the encrypted message is written to a file.
 */

int main() {
    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    FILE *rsa_file;
    RSA *rsa_keypair;

    /* Load the public key from the PEM file */
    if ((rsa_file = fopen("../public.pem", "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open public key file.\n");
        abort();
    }

    /* Read the public key into an RSA structure */
    if ((rsa_keypair = PEM_read_RSAPublicKey(rsa_file, NULL, NULL, NULL)) == NULL)
        handle_errors();
    fclose(rsa_file);

    /* Define the message to be encrypted */
    unsigned char msg[] = "This is the message to be encrypted.";
    unsigned char encrypted_msg[RSA_size(rsa_keypair)];
    int encrypted_length;

    /* Encrypt the message using the public key and OAEP padding */
    if ((encrypted_length = RSA_public_encrypt(strlen(msg) + 1, msg, encrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        handle_errors();

    /* Open the file to write the encrypted message */
    FILE *out;
    if ((out = fopen("../encrypted_msg.enc", "w")) == NULL) {
        fprintf(stderr, "Error: Unable to open file for writing.\n");
        abort();
    }

    /* Write the encrypted message to the file */
    if (fwrite(encrypted_msg, 1, encrypted_length, out) < encrypted_length) {
        fprintf(stderr, "Error: Unable to write to file.\n");
        abort();
    }
    fclose(out);

    printf("Encrypted message written to encrypted_msg.enc\n");

    /* Free the RSA structure */
    RSA_free(rsa_keypair);

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
