/* Padding */

/*
 * Starting from enc1.c, find a way to disable the padding.
 *
 * The flag is the instruction you have to add surrounded by the CRYPTO25{}.
 * Avoid spaces and include the semicolon.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0

int main()
{
    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[]  = "1111111111111111";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT);

    // Disable padding
    EVP_CIPHER_CTX_set_padding(ctx,0);

    unsigned char plaintext[] = "This is the plaintext to encrypt."; //len 33
    unsigned char ciphertext[48];

    int update_len, final_len;
    int ciphertext_len = 0;

    EVP_CipherUpdate(ctx,ciphertext,&update_len,plaintext,strlen(plaintext));
    ciphertext_len += update_len;
    printf("update size: %d\n",ciphertext_len);

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
