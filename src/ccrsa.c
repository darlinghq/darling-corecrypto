#include <corecrypto/ccrsa.h>

int ccrsa_import_pub(ccrsa_pub_ctx_t key, size_t inlen, const uint8_t *der) {
}

cc_size ccder_decode_rsa_pub_n(const uint8_t *der, const uint8_t *der_end) {
}

int ccrsa_pub_crypt(ccrsa_pub_ctx_t key, cc_unit *out, const cc_unit *in) {
}

int ccrsa_generate_key(unsigned long nbits, ccrsa_full_ctx_t rsa_ctx,
                       size_t e_size, const void *e, struct ccrng_state *rng) {
}

int ccrsa_priv_crypt(ccrsa_priv_ctx_t key, cc_unit *out, const cc_unit *in) {
}

cc_size ccder_decode_rsa_priv_n(const uint8_t *der, const uint8_t *der_end) {
}

const uint8_t *ccder_decode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, const uint8_t *der_end) {
}

int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t *oid,
                          size_t digest_len, const uint8_t *digest,
                          size_t sig_len, const uint8_t *sig,
                          bool *valid) {
}

void ccrsa_init_pub(ccrsa_pub_ctx_t key, const cc_unit *modulus,
                    const cc_unit *e) {
}

