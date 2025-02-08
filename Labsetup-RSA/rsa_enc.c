#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM * a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *c = BN_new();

    // Initialize n, e (public key) and message m
    BN_hex2bn(&n, "E103ABD94892E3E74AFD724BF28E78366D9676BCCC70118BD0AA1968DBB143D1");
    BN_hex2bn(&e, "0D88c3"); //(=this hex value equals to decimal 65537)
    BN_hex2bn(&m, "4120746f702073656372657421");

    // Compute ciphertext: c = m^e mod n
    BN_mod_exp(c, m, e, n, ctx);
    
    // Print results
    printBN("Ciphertext:", c);

    // Free memory
    BN_free(n);
    BN_free(e);
    BN_free(m);
    BN_free(c);
    BN_CTX_free(ctx);

    return 0;
}

