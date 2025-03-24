#include <stdio.h>

#include <openssl/bn.h>

int main() {
    /* Define a decimal number string */
    char num_string[] = "123456789012345678901234567890123456789012345678901234567890";

    /* Create new BIGNUM objects */
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    /* Convert the decimal number string to a BIGNUM and store it in bn1 */
    BN_dec2bn(&bn1, num_string);

    /* Print the BIGNUM bn1 */
    printf("bn1: ");
    BN_print_fp(stdout, bn1);
    printf("\n");

    /* Define a hexadecimal number string */
    char hex_string[] = "13AAF504E4BC1E62173F87A4378C37B49C8CCFF196CE3F0AD2";

    /* Convert the hexadecimal number string to a BIGNUM and store it in bn2 */
    BN_hex2bn(&bn2, hex_string);

    /* Print the BIGNUM bn2 */
    printf("bn2: ");
    BN_print_fp(stdout, bn2);
    printf("\n");

    /* Compare bn1 and bn2 and print if they are equal or not */
    BN_cmp(bn1, bn2) == 0 ? printf("bn1 and bn2 are equal\n") : printf("bn1 and bn2 are not equal\n");

    /* Print bn1 in hexadecimal format */
    printf("bn1 = %s\n", BN_bn2hex(bn1));
    /* Print bn2 in decimal format */
    printf("bn2 = %s\n", BN_bn2dec(bn2));

    /* Free the BIGNUM objects */
    BN_free(bn1);
    BN_free(bn2);

    return 0;
}
