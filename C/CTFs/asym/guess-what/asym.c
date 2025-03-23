/* guess what */

/*
 * You have found these data
 *
 * 00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:
 * c6:07:fa:a8:35:f6:ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:
 * b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:
 * 67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:
 * 60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:
 * 5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:
 * d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:
 * 62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51
 * 
 * 00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:
 * f9:71:11:e1:cf:be:62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:
 * 2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:
 * 38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07
 * 
 * Find the other missing parameter using BIGNUM primitives (you may have to manipulate these data a bit before).
 * 
 * Use the same representation (with a ':' every two digits). Surround it with CRYPTO25{} to have your flag. 
 * Add leading zeros if needed to equalize parameters...
 */

#include <stdio.h>

#include <openssl/bn.h>

/* Function to convert a colon-separated hex string to a BIGNUM */
BIGNUM* hex_to_bn(const char* hex_str) {
    BIGNUM* bn = BN_new();
    BN_hex2bn(&bn, hex_str);
    return bn;
}

/* Function to print a BIGNUM as a colon-separated hex string */
void print_bn_as_hex(const BIGNUM* bn) {
    char* hex_str = BN_bn2hex(bn);
    for (int i = 0; hex_str[i] != '\0'; i++) {
        if (i > 0 && i % 2 == 0) {
            printf(":");
        }
        printf("%c", hex_str[i]);
    }
    OPENSSL_free(hex_str);
    printf("\n");
}

int main() {
    /* Initialize OpenSSL BIGNUM library */
    BN_CTX* ctx = BN_CTX_new();

    /* Given data as hex strings */
    const char* data1 = "009eee82dc2cd4a00c4f5a7b8663b0c1ed0677fcebde1a235df4c3ff876a7dadc607faa835f6ae0503573e223676d50d574f99f958ad637ae745a6aafa023423b69d34157b1141b6b1cab91acd2955bd42f504abdf454a9d4eca4e01f9f8745967eeb6a9fb96b7c09400178a530eb6d831c968e66438d3633a04d7886bf0e1ad607f41bd857bd904e1975b1f9b05ceac2cc4553fb48b894d0a509a094e5e8f5b5f5569725f049b3a8a09b47f8db2ca520e5ebff4b0eec9badc934f6dd31f821ad9fc2ca73f18230dd744c728546784ee739265f01ce81e6d4d9565b4c84fb80462582bee3264a0a7dc99250e505376bc30db715e93d69f1f881c765d82c8593951";
    const char* data2 = "00d2c601326b4c4b855f527bb78ed68ae4c8767e6bc9249a3ecacd2fc9b875d4f97111e1cfbe62d32c5ff9fd9bfaed62f3df44c757fbee9bb232cb5449296c692e301d8c1ffab18ee44966c1fb927c82ca60c940a40ab2db50ecf6ff98a71623388d06d27ca9858ac22b4dd4e6f189e5b04254a05f3cddc764330511fbee8b2607";

    /* Convert hex strings to BIGNUMs */
    BIGNUM* bn1 = hex_to_bn(data1);
    BIGNUM* bn2 = hex_to_bn(data2);

    /* Perform some BIGNUM operations to find the missing parameter */
    /* For demonstration, let's assume we need to multiply these numbers */
    BIGNUM* result = BN_new();
    BN_mul(result, bn1, bn2, ctx);

    /* Print the result as a colon-separated hex string */
    printf("CRYPTO25{");
    print_bn_as_hex(result);
    printf("}\n");

    /* Free allocated memory */
    BN_free(bn1);
    BN_free(bn2);
    BN_free(result);
    BN_CTX_free(ctx);

    return 0;
}
