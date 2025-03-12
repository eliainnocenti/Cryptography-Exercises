#include <stdio.h>

#include <openssl/rand.h> // OpenSSL library for random number generation

#define MAX 64 // Define the maximum length of the random string

int main() {

    unsigned char random_string[MAX]; // Array to hold the random bytes

    /* Load random data from /dev/random, optional for Linux */
    /* Returns the number of bytes read, or -1 on error */
    /* Print an error message if the loading fails */
    if (RAND_load_file("/dev/random", 64) != 64)
        fprintf(stderr, "Error with rand init\n");

    /* Generate random bytes and store them in random_string */
    /* Print an error message if the generation fails */
    if (!RAND_bytes(random_string, MAX))
        fprintf(stderr, "Error with rand generation\n");

    printf("Sequence generated: ");

    /* Loop through the random_string array and print each byte in hexadecimal format */
    for (int i = 0; i < MAX; i++)
        printf("%02x-", random_string[i]);

    printf("\n");

    return 0;

}
