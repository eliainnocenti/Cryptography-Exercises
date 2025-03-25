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
 * Main function to decrypt an encrypted message using a private RSA key.
 * The private key is loaded from a PEM file, and the encrypted message is read from a file.
 */

int main() {
    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    FILE *rsa_file;
    RSA *rsa_keypair;

    /* Load the private key from the PEM file */
    if ((rsa_file = fopen("../private.pem", "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open private key file.\n");
        abort();
    }

    /* Read the private key into an RSA structure */
    if ((rsa_keypair = PEM_read_RSAPrivateKey(rsa_file, NULL, NULL, NULL)) == NULL)
        handle_errors();
    fclose(rsa_file);

    printf("I'm reading the encrypted message from the file.\n");

    /* Open the file containing the encrypted message */
    FILE *in;
    if ((in = fopen("../encrypted_msg.enc", "r")) == NULL) {
        fprintf(stderr, "Error: Unable to open file for reading.\n");
        abort();
    }

    /* Determine the size of the encrypted message */
    fseek(in, 0, SEEK_END);
    long enc_msg_len = ftell(in);
    fseek(in, 0, SEEK_SET);

    /* Allocate memory to store the encrypted message */
    unsigned char encrypted_msg[enc_msg_len];
    if (fread(encrypted_msg, 1, enc_msg_len, in) != enc_msg_len) {
        fprintf(stderr, "Error: Unable to read the encrypted message.\n");
        abort();
    }
    fclose(in);

    /* Allocate memory to store the decrypted message */
    unsigned char decrypted_msg[RSA_size(rsa_keypair)];
    int decrypted_length;

    /* Decrypt the encrypted message using the private key and OAEP padding */
    if ((decrypted_length = RSA_private_decrypt(enc_msg_len, encrypted_msg, decrypted_msg, rsa_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        handle_errors();

    /* Print the decrypted message */
    printf("Decrypted message: \"%s\"\n", decrypted_msg);

    /* Free the RSA structure */
    RSA_free(rsa_keypair);

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
