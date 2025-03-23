/* Keyed digest */

/*
 * Given the secret (represented as a C variable)
 *
 * unsigned char secret[] = "this_is_my_secret";
 * 
 * Write a program in C that computes the keyed digest as
 * 
 *  kd = SHA512 ( secret || input_file || secret)
 * 
 *  - where || indicates the concatenation (without adding any space characters)
 *  - hex computes the representation as an hexstring
 * 
 * Surround with CRYPTO25{hex(kd)} to obtain the flag.
 * HINT: start from hash3.c or hash4.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024

/* Secret key */
unsigned char secret[] = "this_is_my_secret";

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]);
        exit(1);
    }

    /* Open the input file */
    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }

    /* Create a new digest context */
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == NULL) {
        fprintf(stderr, "Failed to create digest context\n");
        exit(1);
    }

    /* Initialize the digest context with SHA512 */
    if (EVP_DigestInit(md, EVP_sha512()) != 1) {
        fprintf(stderr, "Failed to initialize digest context\n");
        EVP_MD_CTX_free(md);
        exit(1);
    }

    /* Update the digest with the first secret */
    if (EVP_DigestUpdate(md, secret, strlen((char *)secret)) != 1) {
        fprintf(stderr, "Failed to update digest with secret\n");
        EVP_MD_CTX_free(md);
        exit(1);
    }

    /* Read the input file and update the digest */
    int n;
    unsigned char buffer[MAXBUF];
    while ((n = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        if (EVP_DigestUpdate(md, buffer, n) != 1) {
            fprintf(stderr, "Failed to update digest with file content\n");
            EVP_MD_CTX_free(md);
            exit(1);
        }
    }

    /* Update the digest with the second secret */
    if (EVP_DigestUpdate(md, secret, strlen((char *)secret)) != 1) {
        fprintf(stderr, "Failed to update digest with secret\n");
        EVP_MD_CTX_free(md);
        exit(1);
    }

    /* Finalize the digest */
    unsigned char md_value[EVP_MD_size(EVP_sha512())];
    unsigned int md_len;
    if (EVP_DigestFinal_ex(md, md_value, &md_len) != 1) {
        fprintf(stderr, "Failed to finalize digest\n");
        EVP_MD_CTX_free(md);
        exit(1);
    }

    /* Free the digest context */
    EVP_MD_CTX_free(md);

    /* Print the digest as a hex string */
    printf("CRYPTO25{");
    for (unsigned int i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]);
    }
    printf("}\n");

    /* Close the input file */
    fclose(f_in);

    return 0;
}
