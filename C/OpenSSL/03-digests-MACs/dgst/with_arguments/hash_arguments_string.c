#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

int main(int argc, char **argv) {
    /* Check if the correct number of arguments is provided */
    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s <message>\n", argv[0]);
        exit(1);
    }

    EVP_MD_CTX *mdctx;

    /* Create a new digest context */
    mdctx = EVP_MD_CTX_new();

    /* Initialize the digest context for SHA-1 */
    EVP_DigestInit(mdctx, EVP_sha1());

    /* Update the digest with the input string */
    EVP_DigestUpdate(mdctx, argv[1], strlen(argv[1]));

    unsigned char md_value[EVP_MD_size(EVP_sha1())]; // Buffer to hold the final digest
    int md_len;

    /* Finalize the digest and obtain the result */
    EVP_DigestFinal(mdctx, md_value, &md_len);

    /* Free the digest context */
    EVP_MD_CTX_free(mdctx);

    /* Print the resulting digest in hexadecimal format */
    printf("The digest is: ");
    for (int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    return 0;
}
