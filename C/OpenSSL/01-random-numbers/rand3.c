#include <stdio.h>

#include <openssl/rand.h> // OpenSSL library for random number generation
#include <openssl/err.h>  // OpenSSL library for error handling

#define MAX 64 // Define the maximum length of the random string

/* Function to handle errors by printing them to stderr and aborting the program */
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {

    unsigned char random_string[MAX]; // Array to hold the random bytes

    /* Load random data from /dev/random, optional for Linux */
    /* Call handle_errors() if the loading fails */
    if (RAND_load_file("/dev/random", 64) != 64)
        handle_errors();

    /* Generate random bytes and store them in random_string */
    /* Call handle_errors() if the generation fails */
    if (!RAND_bytes(random_string, MAX))
        handle_errors();

    printf("Sequence generated: ");

    /* Loop through the random_string array and print each byte in hexadecimal format */
    for (int i = 0; i < MAX; i++)
        printf("%02x-", random_string[i]);

    printf("\n");

    return 0;

}
