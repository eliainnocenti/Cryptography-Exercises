#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>

/* Function to handle errors by printing them and aborting the program */
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    /* Load the human-readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Create new BIGNUM objects for prime numbers */
    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();

    /* Generate a 1024-bit prime number and store it in prime1 */
    if (!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    // Deprecated in OpenSSL 3.0
    // Use BN_generate_prime_ex2() + context instead

    /*
     * Function to generate prime numbers.
     * Parameters:
     * - ret: Reference to the BIGNUM object where the prime number will be stored.
     * - bits: Number of bits for the prime number.
     * - safe: If true, ensures (p-1)/2 is also prime.
     * - add: Optional parameter to force the prime number generation such that p % add == rem.
     * - rem: Optional parameter to specify the remainder when p is divided by add.
     *        If rem is NULL, it defaults to 1.
     *        If rem is NULL and safe is true, it defaults to 3 and add must be a multiple of 4.
     * - cb: Callback function for progress indication.
     */

    /* Print the generated prime number */
    printf("prime1: ");
    BN_print_fp(stdout, prime1);
    printf("\n");

    /* Check if prime1 is a prime number */
    if (BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("prime1 is prime\n");
    else
        printf("prime1 is not prime\n");

    // BN_check_prime(prime_num, ctx, cb) --> check if prime_num is prime

    /* Set prime2 to the value 16 */
    BN_set_word(prime2, 16);

    /* Check if prime2 is a prime number */
    if (BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("prime2 is prime\n");
    else
        printf("prime2 is not prime\n");

    /* Print the number of bits and bytes in prime1 */
    printf("number of bits in prime1: %d\n", BN_num_bits(prime1));
    printf("number of bytes in prime1: %d\n", BN_num_bytes(prime1));

    /* Print the number of bits and bytes in prime2 */
    printf("number of bits in prime2: %d\n", BN_num_bits(prime2));
    printf("number of bytes in prime2: %d\n", BN_num_bytes(prime2));

    /* Free the BIGNUM objects */
    BN_free(prime1);
    BN_free(prime2);

    /* Completely free all the cipher data */
    CRYPTO_cleanup_all_ex_data();
    
    /* Remove error strings */
    ERR_free_strings();

    return 0;
}
