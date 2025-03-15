/* In the Name of the Cipher */

/*
 * Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.
 *
 * The input filename is passed as first parameter from the command line, key and IV are the second and third parameter,
 * the output file is the fourth parameter, the algorithm is the last parameter.
 * 
 * The algorithm name must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb). (In short, you have to extend enc4.c)
 * 
 * Look for the proper function here https://www.openssl.org/docs/man3.1/man3/EVP_EncryptInit.html
 * 
 * In doing the exercise you have found a very relevant function, build the flag as "CRYPTO25{" + relevantFunctionName + "}"
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

#define MAX_BUFFER 1024

void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argcv) {

    return 0;
}