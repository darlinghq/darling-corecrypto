#include <corecrypto/ccrsa_priv.h>

int ccrsa_oaep_encode_parameter(const struct ccdigest_info* di,
                                struct ccrng_state *rng,
                                size_t r_size, cc_unit *r,
                                size_t message_len, const uint8_t *message,
                                size_t parameter_data_len, const uint8_t *parameter_data) {
}

int ccrsa_oaep_decode_parameter(const struct ccdigest_info* di,
                                size_t *r_len, uint8_t *r,
                                size_t s_size, cc_unit *s,
                                size_t parameter_data_len, const uint8_t *parameter_data) {
}

CC_NONNULL_TU((1)) CC_NONNULL((2, 3, 4, 6))
int ccrsa_encrypt_eme_pkcs1v15(ccrsa_pub_ctx_t key,
                           struct ccrng_state *rng,
                           size_t *r_size, uint8_t *r,
                           size_t s_size, const uint8_t *s) {
}

CC_NONNULL_TU((1)) CC_NONNULL((2, 3, 4, 5, 7))
int ccrsa_encrypt_oaep(ccrsa_pub_ctx_t key,
                   const struct ccdigest_info* di,
                   struct ccrng_state *rng,
                   size_t *r_size, uint8_t *r,
                   size_t s_size, uint8_t *s,
                   size_t parameter_data_len,
                   const uint8_t *parameter_data) {
}

CC_NONNULL_TU((1)) CC_NONNULL((2, 3, 5))
int ccrsa_decrypt_eme_pkcs1v15(ccrsa_full_ctx_t key,
                           size_t *r_size, uint8_t *r,
                           size_t s_size, uint8_t *s) {
}

CC_NONNULL_TU((1)) CC_NONNULL((2, 3, 4, 6))
int ccrsa_decrypt_oaep(ccrsa_full_ctx_t key,
                   const struct ccdigest_info* di,
                   size_t *r_size, uint8_t *r,
                       size_t c_size, uint8_t *c,
                       size_t parameter_data_len,
                       const uint8_t *parameter_data) {
}

CC_NONNULL_TU((1,4,7)) CC_NONNULL((2, 3, 5, 6, 8))
int ccrsa_crt_makekey(cczp_t zm, const cc_unit *e, cc_unit *d, cczp_t zp, cc_unit *dp, cc_unit *qinv, cczp_t zq, cc_unit *dq) {
}
