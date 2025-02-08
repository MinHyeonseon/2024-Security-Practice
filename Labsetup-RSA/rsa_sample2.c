#include <stdio.h>
#include <openssl/bn.h>

// Function to print a BIGNUM as a hexadecimal string
void printBN(char *msg, BIGNUM * a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new(); // Context for big number operations
    BIGNUM *n = BN_new();       // Modulus
    BIGNUM *d = BN_new();       // Private key
    BIGNUM *m = BN_new();       // Message as a big number
    BIGNUM *s = BN_new();       // Signature

    // Initialize n (modulus), d (private key), and message m
    BN_hex2bn(&n, "E103ABD94892E3E74AFD724BF28E78366D9676BCCC70118BD0AA1968DBB143D1");
    BN_hex2bn(&d, "3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB");

    // Convert the message "I owe you $2000." into hexadecimal and assign it to m
    // "I owe you $2000." in hexadecimal: 49206F776520796F752024323030302E
    BN_hex2bn(&m, "49206f776520796f752024323030302e");

    // Generate the signature: s = m^d mod n
    BN_mod_exp(s, m, d, n, ctx);

    // Print the signature
    printBN("Signature (hex):", s);

    // Free allocated memory
    BN_free(n);
    BN_free(d);
    BN_free(m);
    BN_free(s);
    BN_CTX_free(ctx);

    return 0;
}

