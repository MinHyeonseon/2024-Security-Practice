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
    BIGNUM *e = BN_new();       // Public key exponent
    BIGNUM *s = BN_new();       // Signature
    BIGNUM *m_verified = BN_new(); // Verified message from signature
    BIGNUM *m_original = BN_new(); // Original message in BIGNUM format

    // Initialize n, e (public key), and signature s
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
    BN_hex2bn(&e, "010001"); // e = 65537
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // Original message M = "Launch a missile." in hexadecimal
    BN_hex2bn(&m_original, "4C61756E63682061206D697373696C652E"); // "Launch a missile." in hex

    // Verify the signature: m_verified = s^e mod n
    BN_mod_exp(m_verified, s, e, n, ctx);

    // Print the verified message
    printBN("Verified message (hex):", m_verified);

    // Compare verified message with the original message
    if (BN_cmp(m_verified, m_original) == 0) {
        printf("The signature is valid.\n");
    } else {
        printf("The signature is invalid.\n");
    }

    // Free allocated memory
    BN_free(n);
    BN_free(e);
    BN_free(s);
    BN_free(m_verified);
    BN_free(m_original);
    BN_CTX_free(ctx);

    return 0;
}

