#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define MAXBUF 1024 // Define the maximum buffer size for reading the file

int main(int argc, char **argv) {
    /* Check if the correct number of arguments is provided */
    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s <message>\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    /* Try to open the input file for reading */
    if ((f_in = fopen(argv[1], "r")) == NULL) {
        fprintf(stderr, "Error opening the input file: %s\n", argv[1]);
        exit(1);
    }

    EVP_MD_CTX *mdctx;

    /* Create a new digest context */
    mdctx = EVP_MD_CTX_new();

    /* Initialize the digest context for SHA-1 */
    EVP_DigestInit(mdctx, EVP_sha1());

    unsigned char buffer[MAXBUF]; // Buffer to hold file data
    int n_read;

    /* Read the file and update the digest with the file's content */
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, n_read);
    }

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
