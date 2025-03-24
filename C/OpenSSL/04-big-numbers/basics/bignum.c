#include <stdio.h>

#include <openssl/bn.h>

int main() {
    /* Create new BIGNUM objects */
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    /* Print the initial value of bn1 (which is 0) */
    printf("bn1: ");
    BN_print_fp(stdout, bn1);
    printf("\n");

    /* Set bn1 to the value 1234567890 */
    BN_set_word(bn1, 1234567890); // unsigned long to BIGNUM
    /* Print the value of bn1 */
    printf("bn1: ");
    BN_print_fp(stdout, bn1);
    printf("\n");

    /* Set bn2 to the value 9876543210 */
    BN_set_word(bn2, 9876543210); // unsigned long to BIGNUM
    /* Print the value of bn2 */
    printf("bn2: ");
    BN_print_fp(stdout, bn2);
    printf("\n");

    /* Create a new BIGNUM object for the result */
    BIGNUM *res = BN_new();

    /* Add bn1 and bn2 and store the result in res */
    BN_add(res, bn1, bn2); // res = bn1 + bn2
    /* Print the result of bn1 + bn2 */
    printf("bn1 + bn2: ");
    BN_print_fp(stdout, res);
    printf("\n");

    /* Create a new BN_CTX object for temporary variables */
    BN_CTX *ctx = BN_CTX_new();
    /* Compute bn1 mod bn2 and store the result in res */
    printf("bn1 mod bn2: ");
    BN_mod(res, bn1, bn2, ctx); // res = bn1 % bn2
    /* Print the result of bn1 mod bn2 */
    BN_print_fp(stdout, res);
    printf("\n");

    /* Free the BIGNUM objects and the BN_CTX object */
    BN_free(bn1);
    BN_free(bn2);
    BN_free(res);
    BN_CTX_free(ctx);

    return 0;
}
