#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main() {
    /* Create a new cipher context */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Check for NULL

    /* Define the key and IV (Initialization Vector) */
    unsigned char key[] = "1234567890abcdef"; // ASCII
    unsigned char iv[] = "1234567890abcdef";  // ASCII

    /* Initialize the encryption operation */
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);

    /* Define the plaintext to be encrypted */
    unsigned char plaintext[] = "This variable contains the data to be encrypted."; // 48 bytes long
    unsigned char ciphertext[48]; // 48 bytes long

    int len = 0; // Temporary output of the Update function
    int ciphertext_len = 0;

    /* Encrypt the plaintext */
    EVP_CipherUpdate(ctx, ciphertext, &len, plaintext, strlen(plaintext));

    printf("After update: %d\n", len);
    ciphertext_len += len;

    /* Finalize the encryption */
    EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &len);

    printf("After final: %d\n", len);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext: %d\n", ciphertext_len);

    /* Print the ciphertext in hex format */
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
