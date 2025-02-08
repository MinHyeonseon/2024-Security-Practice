#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a) {
    char *number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main() {
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *p1 = BN_new();
    BIGNUM *q1 = BN_new();

    // Initialize p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_dec2bn(&one, "1");

    // n = p * q
    BN_mul(n, p, q, ctx);
    printBN("n = ", n);

    // phi = (p-1) * (q-1)
    BN_sub(p1, p, one);
    BN_sub(q1, q, one);
    BN_mul(phi, p1, q1, ctx);
    printBN("phi(n) = ", phi);

    // d = e^(-1) mod phi
    BN_mod_inverse(d, e, phi, ctx);
    printBN("d = ", d);

    // Free memory
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(phi);
    BN_free(d);
    BN_free(one);
    BN_free(p1);
    BN_free(q1);
    BN_CTX_free(ctx);

    return 0;
}

