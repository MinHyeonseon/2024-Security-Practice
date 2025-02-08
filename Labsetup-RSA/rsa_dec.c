#include <stdio.h>
#include <openssl/bn.h>

// Function to print a BIGNUM as a hexadecimal string
void printBN(char *msg, BIGNUM * a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new(); 
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();      
    BIGNUM *c = BN_new();       
    BIGNUM *m = BN_new();       

    // Initialize n (modulus), d (private key), and c (ciphertext)
    BN_hex2bn(&n, "E103ABD94892E3E74AFD724BF28E78366D9676BCCC70118BD0AA1968DBB143D1");
    BN_hex2bn(&d, "3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB");
    BN_hex2bn(&c, "90A81343DFE08415EDF79337CDE00457BAB56AFFA1B0CE5647BF9025665B396A");

    // Decrypt: m = c^d mod n
    BN_mod_exp(m, c, d, n, ctx);

    // Print results
    printBN("Decrypted message (hex):", m);

    BN_free(n);
    BN_free(d);
    BN_free(c);
    BN_free(m);
    BN_CTX_free(ctx);

    return 0;
}
