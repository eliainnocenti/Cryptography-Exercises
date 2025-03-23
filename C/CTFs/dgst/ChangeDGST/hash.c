/* ChangeDGST */

/*
 * Starting from the file hash3.c, change the code to compute the SHA256.
 * 
 * After having modified it, compute the hash of the modified file 
 * (do not add any space, newlines, just do the minimum number of changes).
 * 
 * The flag will be "CRYPTO25{" + hex(SHA256digest(new_file) + "}" where newfile is the hash3.c 
 * after the modifications and hex() is the function that represents the binary digest as a string of hex digits.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

/* Function to compute the SHA256 hash of a file */
void compute_sha256(const char *filename) {
    /* Open the file for reading */
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Couldn't open the file %s\n", filename);
        return;
    }

    /* Create a new digest context */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Couldn't create digest context\n");
        fclose(file);
        return;
    }

    /* Initialize the digest context for SHA256 */
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "Couldn't initialize digest context\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    /* Read the file and update the digest */
    unsigned char buffer[1024];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, bytes_read)) {
            fprintf(stderr, "Couldn't update digest\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return;
        }
    }

    /* Finalize the digest */
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        fprintf(stderr, "Couldn't finalize digest\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    /* Clean up */
    EVP_MD_CTX_free(mdctx);
    fclose(file);

    /* Print the hash as a hex string */
    printf("SHA256(%s) = ", filename);
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    /* Check if the correct number of arguments is provided */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    /* Compute the SHA256 hash of the provided file */
    compute_sha256(argv[1]);

    return 0;
}
