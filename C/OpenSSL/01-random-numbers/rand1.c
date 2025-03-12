#include <stdio.h>

#include <openssl/rand.h> // OpenSSL library for random number generation

#define MAX 64 // Define the maximum length of the random string

int main() {

    unsigned char random_string[MAX]; // Array to hold the random bytes

    /* Load random data from /dev/random, optional for Linux */
    RAND_load_file("/dev/random", 64);

    /* Generate random bytes and store them in random_string */
    RAND_bytes(random_string, MAX);

    printf("Sequence generated: ");

    /* Loop through the random_string array and print each byte in hexadecimal format */
    for (int i = 0; i < MAX; i++)
        printf("%02x-", random_string[i]);

    printf("\n");

    return 0;

}