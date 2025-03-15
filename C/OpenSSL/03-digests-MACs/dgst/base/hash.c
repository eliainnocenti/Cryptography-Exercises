#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

int main() {
    /* Message to be hashed */
    char message[] = "This is the message to be hashed!";

    EVP_MD_CTX *mdctx;

    /* Create a new digest context */
    mdctx = EVP_MD_CTX_new();

    /* Initialize the digest context for SHA-1 */
    EVP_DigestInit(mdctx, EVP_sha1());

    /* Update the digest with the message */
    EVP_DigestUpdate(mdctx, message, strlen(message));

    unsigned char md_value[20]; // SHA-1 produces a 160-bit hash value
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
