/*
 * Small OpenSSL harness for building reference static-linked ELF binaries.
 *
 * The goal is not to implement a useful crypto tool; it is to force the linker
 * to pull representative OpenSSL objects from libssl.a/libcrypto.a so vSim can
 * extract function-level fingerprints from a complete executable.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

static volatile unsigned int sink;

static void absorb(const unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        sink = (sink * 33u) ^ buf[i];
    }
}

static int exercise_evp_hash_hmac_cipher(void)
{
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    unsigned char input[64] = "static openssl harness sample payload";
    unsigned char encrypted[96];
    unsigned char decrypted[96];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int out_len = 0;
    int total_len = 0;

    memset(encrypted, 0, sizeof(encrypted));
    memset(decrypted, 0, sizeof(decrypted));

    if (!EVP_Digest(input, sizeof(input), digest, &digest_len, EVP_sha256(), NULL)) {
        return 1;
    }
    absorb(digest, digest_len);

    if (HMAC(EVP_sha256(), key, 32, input, sizeof(input), digest, &digest_len) == NULL) {
        return 1;
    }
    absorb(digest, digest_len);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    {
        EVP_CIPHER_CTX ctx_storage;
        EVP_CIPHER_CTX *ctx = &ctx_storage;

        EVP_CIPHER_CTX_init(ctx);
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        if (!EVP_EncryptUpdate(ctx, encrypted, &out_len, input, (int)sizeof(input))) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        total_len = out_len;
        if (!EVP_EncryptFinal_ex(ctx, encrypted + total_len, &out_len)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        total_len += out_len;
        EVP_CIPHER_CTX_cleanup(ctx);

        EVP_CIPHER_CTX_init(ctx);
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        if (!EVP_DecryptUpdate(ctx, decrypted, &out_len, encrypted, total_len)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        if (!EVP_DecryptFinal_ex(ctx, decrypted + out_len, &total_len)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            return 1;
        }
        EVP_CIPHER_CTX_cleanup(ctx);
    }
#else
    {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (ctx == NULL) {
            return 1;
        }
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        if (!EVP_EncryptUpdate(ctx, encrypted, &out_len, input, (int)sizeof(input))) {
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        total_len = out_len;
        if (!EVP_EncryptFinal_ex(ctx, encrypted + total_len, &out_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        total_len += out_len;
        EVP_CIPHER_CTX_free(ctx);

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            return 1;
        }
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        if (!EVP_DecryptUpdate(ctx, decrypted, &out_len, encrypted, total_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        if (!EVP_DecryptFinal_ex(ctx, decrypted + out_len, &total_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        EVP_CIPHER_CTX_free(ctx);
    }
#endif

    absorb(encrypted, sizeof(encrypted));
    absorb(decrypted, sizeof(decrypted));
    return 0;
}

static int exercise_low_level_aes(void)
{
    AES_KEY aes_key;
    unsigned char key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned char input[32] = "low level aes block data.......";
    unsigned char output[32];

    memset(output, 0, sizeof(output));
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
        return 1;
    }
    AES_cbc_encrypt(input, output, sizeof(input), &aes_key, iv, AES_ENCRYPT);
    absorb(output, sizeof(output));
    return 0;
}

static int exercise_rsa(void)
{
    int rc = 1;
    RSA *rsa = NULL;
    BIGNUM *e = NULL;
    unsigned char input[32] = "rsa sample";
    unsigned char encrypted[256];
    unsigned char decrypted[256];
    int encrypted_len;
    int decrypted_len;

    memset(encrypted, 0, sizeof(encrypted));
    memset(decrypted, 0, sizeof(decrypted));

    rsa = RSA_new();
    e = BN_new();
    if (rsa == NULL || e == NULL) {
        goto done;
    }
    if (!BN_set_word(e, RSA_F4)) {
        goto done;
    }
    if (!RSA_generate_key_ex(rsa, 1024, e, NULL)) {
        goto done;
    }
    encrypted_len = RSA_public_encrypt(
        (int)strlen((const char *)input), input, encrypted, rsa, RSA_PKCS1_PADDING
    );
    if (encrypted_len <= 0) {
        goto done;
    }
    decrypted_len = RSA_private_decrypt(encrypted_len, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decrypted_len <= 0) {
        goto done;
    }
    absorb(encrypted, (size_t)encrypted_len);
    absorb(decrypted, (size_t)decrypted_len);
    rc = 0;

done:
    RSA_free(rsa);
    BN_free(e);
    return rc;
}

static int exercise_ec_ecdsa(void)
{
    int rc = 1;
    EC_KEY *key = NULL;
    unsigned char digest[32] = {
        0x6b, 0x86, 0xb2, 0x73, 0xff, 0x34, 0xfc, 0xe1,
        0x9d, 0x6b, 0x80, 0x4e, 0xff, 0x5a, 0x3f, 0x57,
        0x47, 0xad, 0xa4, 0xea, 0xa2, 0x2f, 0x1d, 0x49,
        0xc0, 0x1e, 0x52, 0xdd, 0xb7, 0x87, 0x5b, 0x4b
    };
    unsigned char sig[256];
    unsigned int sig_len = 0;

    memset(sig, 0, sizeof(sig));

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL) {
        goto done;
    }
    if (!EC_KEY_generate_key(key)) {
        goto done;
    }
    if (!ECDSA_sign(0, digest, sizeof(digest), sig, &sig_len, key)) {
        goto done;
    }
    if (ECDSA_verify(0, digest, sizeof(digest), sig, sig_len, key) != 1) {
        goto done;
    }
    absorb(sig, sig_len);
    rc = 0;

done:
    EC_KEY_free(key);
    return rc;
}

static int exercise_ssl_context(void)
{
    int rc = 1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_METHOD *method = NULL;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    method = SSLv23_method();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    method = TLS_method();
#endif

    if (method == NULL) {
        goto done;
    }
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        goto done;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto done;
    }
    SSL_set_connect_state(ssl);
    absorb((const unsigned char *)SSL_get_version(ssl), strlen(SSL_get_version(ssl)));
    rc = 0;

done:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return rc;
}

int main(void)
{
    int rc = 0;

    if (RAND_poll() != 1) {
        rc = 1;
    }
    rc |= exercise_evp_hash_hmac_cipher();
    rc |= exercise_low_level_aes();
    rc |= exercise_rsa();
    rc |= exercise_ec_ecdsa();
    rc |= exercise_ssl_context();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    printf("OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
#else
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
#endif
    printf("harness sink: %u\n", sink);
    ERR_print_errors_fp(stderr);
    return rc;
}
