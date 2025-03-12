/* Bytewise operations */

/*
 * A program performs the following operations:
 * - generates two random strings (rand1 and rand2)
 * - perform the bytewise OR of rand1 and rand2 and obtains k1
 * - perform the bytewise AND of rand1 and rand2 and obtains k2
 * - perform the bytewise XOR of k1 and k2 and obtains key
 * 
 * Write the program that implements the bytewise operations.
 * 
 * The flag will be the result (key) when the randomly generated strings are:
 * 
 * rand1 = ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08 
 * rand2 = 4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2
 * 
 * It needs to be printed exactly in the same format as the random numbers (i.e., two hexdigits then a dash) and surrounded by CRYPTO25{}.
 */

#include <stdio.h>

#define L 64

/* Function to print the key in the required format */
void print_key(unsigned char *key) {
    printf("CRYPTO25{");
    for (int i = 0; i < L; i++)
        printf("%02x-", key[i]);
    printf("\b}\n"); // Remove the last dash
}

int main() {

    /* First random string */
    unsigned char rand1[L] = {
        0xed, 0x8a, 0x3b, 0xe8, 0x17, 0x68, 0x38, 0x78, 
        0xf6, 0xb1, 0x77, 0x3e, 0x73, 0xb3, 0xf7, 0x97, 
        0xf3, 0x00, 0x47, 0x76, 0x54, 0xee, 0x8d, 0x51, 
        0x0a, 0x2f, 0x10, 0x79, 0x17, 0xf8, 0xea, 0xd8, 
        0x81, 0x83, 0x6e, 0x0f, 0x0c, 0xb8, 0x49, 0x5a, 
        0x77, 0xef, 0x2d, 0x62, 0xb6, 0x5e, 0xe2, 0x10, 
        0x69, 0xd6, 0xcc, 0xd6, 0xa0, 0x77, 0xa2, 0x0a, 
        0xd3, 0xf7, 0x9f, 0xa7, 0x9e, 0xa7, 0xc9, 0x08
    };

    /* Second random string */
    unsigned char rand2[L] = {
        0x4c, 0x75, 0x82, 0xca, 0x02, 0x07, 0xbd, 0x1d, 
        0x8d, 0x52, 0xf0, 0x6c, 0x7a, 0xd6, 0xb7, 0x87, 
        0x83, 0x95, 0x06, 0x2f, 0xe0, 0xf7, 0xd4, 0x24, 
        0xf8, 0x03, 0x68, 0x97, 0x41, 0x4c, 0x85, 0x29, 
        0xe5, 0x0d, 0xb0, 0xe4, 0x3c, 0xee, 0x74, 0xdc, 
        0x18, 0x8a, 0xaa, 0x26, 0xf0, 0x46, 0x94, 0xe8, 
        0x52, 0x91, 0x4a, 0x43, 0x8f, 0xdd, 0xea, 0xbb, 
        0xa8, 0xcf, 0x51, 0x14, 0x79, 0xec, 0x17, 0xc2
    };

    /* Initialize the arrays to hold the results */
    unsigned char k1[L], k2[L], key[L];

    /* Perform the bytewise operations */
    for (int i = 0; i < L; i++) {
        k1[i] = rand1[i] | rand2[i];  // Bitwise OR
        k2[i] = rand1[i] & rand2[i];  // Bitwise AND
        key[i] = k1[i] ^ k2[i];       // Bitwise XOR
    }

    print_key(key);

    return 0;

}
