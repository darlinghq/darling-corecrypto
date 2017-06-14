// Clang is being weird
#define HIDE_COMPLAINT
#include <corecrypto/ccec.h>

size_t ccec_compact_import_pub_size(size_t in_len) {
}

ccec_const_cp_t ccec_get_cp(size_t keysize) {
}

CC_NONNULL_TU((3)) CC_NONNULL2
void ccec_x963_export(const int fullkey, void *out, ccec_full_ctx_t key) {
}
CC_NONNULL_TU((1,3)) CC_NONNULL2
int ccec_generate_key_legacy(ccec_const_cp_t cp,  struct ccrng_state *rng,
                             ccec_full_ctx_t key) {
}

CC_NONNULL_TU((1))
size_t ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key,
                                  unsigned long flags,
                                  size_t key_len) {
}

CC_NONNULL_TU((1)) CC_NONNULL((2, 6, 7, 8, 9, 10))
int ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key,
                          void  *wrapped_key,
                          unsigned long flags,
                          uint8_t algid,
                          size_t key_len,
                          const void *key,
                          const struct ccec_rfc6637_curve *curve,
                          const struct ccec_rfc6637_wrap *wrap,
                          const uint8_t *fingerprint,
                          struct ccrng_state *rng) {
	return -1;
}

CC_NONNULL_TU((1)) CC_NONNULL((2, 3, 5, 6, 7, 8, 10))
int ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key,
                            size_t *key_len,
                            void *key,
                            unsigned long flags,
                            uint8_t *symm_key_alg,
                            const struct ccec_rfc6637_curve *curve,
                            const struct ccec_rfc6637_unwrap *wrap,
                            const uint8_t *fingerprint,
                            size_t wrapped_key_len,
                            const void  *wrapped_key) {
	return -1;
}

CC_CONST ccec_const_cp_t ccec_cp_192() {
}

CC_CONST ccec_const_cp_t ccec_cp_224() {
}

CC_CONST ccec_const_cp_t ccec_cp_256() {
}

CC_CONST ccec_const_cp_t ccec_cp_384() {
}

CC_NONNULL_TU((1,3)) CC_NONNULL2
int ccec_compact_generate_key(ccec_const_cp_t cp,  struct ccrng_state *rng,
                              ccec_full_ctx_t key) {
}

CC_NONNULL_TU((3)) CC_NONNULL2
void ccec_compact_export(const int fullkey, void *out, ccec_full_ctx_t key) {
}

size_t ccec_x963_import_pub_size(size_t in_len) {
}

int ccec_keysize_is_supported(size_t keysize) {
}

size_t ccec_x963_import_priv_size(size_t in_len) {
}

CC_CONST ccec_const_cp_t ccec_cp_521(void) {
}

CC_NONNULL_TU((1,4)) CC_NONNULL((3))
int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in,
                    ccec_pub_ctx_t key) {
}

CC_NONNULL_TU((1))
size_t
ccec_signature_r_s_size(ccec_full_ctx_t key) {
}

CC_NONNULL_TU((1)) CC_NONNULL((3, 4, 5, 6))
int ccec_verify_composite(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                          uint8_t *sig_r, uint8_t *sig_s, bool *valid) {
}

CC_NONNULL_TU((1)) CC_NONNULL((3, 5, 6))
int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                size_t sig_len, const uint8_t *sig,  bool *valid) {
}

CC_NONNULL_TU((1)) CC_NONNULL2
void ccec_export_pub(ccec_pub_ctx_t key, void *out) {
}

CC_NONNULL_TU((1,4)) CC_NONNULL((3))
int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *data, ccec_full_ctx_t full_key) {
}

CC_NONNULL_TU((1,3)) CC_NONNULL2
int ccec_generate_key_fips(ccec_const_cp_t cp,  struct ccrng_state *rng,
                           ccec_full_ctx_t key) {
}

CC_NONNULL_TU((1)) CC_NONNULL((3, 4, 5, 6))
int ccec_sign_composite(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
                        uint8_t *sig_r, uint8_t *sig_s, struct ccrng_state *rng) {
}

CC_NONNULL_TU((1)) CC_NONNULL((3, 4, 5, 6))
int ccec_sign(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
              size_t *sig_len, uint8_t *sig, struct ccrng_state *rng) {
}

CC_NONNULL_TU((3)) CC_NONNULL((2,4))
int ccec_der_import_priv_keytype(size_t len, const uint8_t * data, ccoid_t *oid, size_t *n) {
}

const ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...) {
}

CC_NONNULL_TU((1,4)) CC_NONNULL3
int ccec_compact_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key) {
}

CC_NONNULL_TU((1,2)) CC_NONNULL((3, 4))
int ccec_compute_key(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
                     size_t *computed_key_len, uint8_t *computed_key) {
}

int ccec_generate_key(ccec_const_cp_t cp, struct ccrng_state *rng,
                      ccec_full_ctx_t key) {
}

CC_NONNULL_TU((1,2)) CC_NONNULL((3, 4))
int ccecdh_compute_shared_secret(ccec_full_ctx_t private_key,
                                 ccec_pub_ctx_t public_key,
                                 size_t *computed_shared_secret_len, uint8_t *computed_shared_secret,
                                 struct ccrng_state *masking_rng) {
}

CC_NONNULL_TU((1))
int ccec_get_pubkey_components(ccec_pub_ctx_t key, size_t *nbits,
                           uint8_t *x, size_t *xsize,
                           uint8_t *y, size_t *ysize) {
}

CC_NONNULL_TU((1))
int ccec_get_fullkey_components(ccec_full_ctx_t key, size_t *nbits,
                            uint8_t *x, size_t *xsize,
                            uint8_t *y, size_t *ysize,
                            uint8_t *d, size_t *dsize) {
}

CC_NONNULL_TU((6))
int ccec_make_pub(size_t nbits,
                  size_t xlength, uint8_t *x,
                  size_t ylength, uint8_t *y,
                  ccec_pub_ctx_t key) {
}

CC_NONNULL_TU((8))
int ccec_make_priv(size_t nbits,
                   size_t xlength, uint8_t *x,
                   size_t ylength, uint8_t *y,
                   size_t klength, uint8_t *k,
                   ccec_full_ctx_t key) {
}

CC_NONNULL_TU((1,4)) CC_NONNULL3
int ccec_x963_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key) {
}

CC_NONNULL_TU((1,4)) CC_NONNULL3
int ccec_x963_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key) {
}

size_t ccec_compact_import_priv_size(size_t in_len) {
	return 1;
}

CC_NONNULL_TU((1,4)) CC_NONNULL3
int ccec_compact_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key) {
	return -1;
}
 
// Guessed
int ccec_generate_key_deterministic(ccec_const_cp_t arg0, int arg1, unsigned char *arg2, struct ccrng_state *arg3, int arg4, int arg5) {
	return -1;
}
