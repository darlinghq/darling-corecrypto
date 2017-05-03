#include <corecrypto/ccdh.h>

CC_NONNULL_TU((1,2)) CC_NONNULL3
int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key,
                     cc_unit *computed_key) {
}

CC_NONNULL_TU((1)) CC_NONNULL3
int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                    ccdh_pub_ctx_t key) {
}

CC_NONNULL_TU((1)) CC_NONNULL2
int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng,
                      ccdh_full_ctx_t key) {
}

cc_size ccder_decode_dhparam_n(const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL_TU((1)) CC_NONNULL((2))
const uint8_t *ccder_decode_dhparams(ccdh_gp_t gp, const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL_TU((1)) CC_NONNULL2
void ccdh_export_pub(ccdh_pub_ctx_t key, void *out) {
}

