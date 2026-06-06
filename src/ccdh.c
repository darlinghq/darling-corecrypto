#include <corecrypto/ccdh.h>
#include <stdio.h>

int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key,
                     cc_unit *computed_key) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                    ccdh_pub_ctx_t key) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng,
                      ccdh_full_ctx_t key) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_size ccder_decode_dhparam_n(const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_dhparams(ccdh_gp_t gp, const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccdh_export_pub(ccdh_pub_ctx_t key, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccdh_init_gp(ccdh_gp_t gp, cc_size n, cc_unit *p, cc_unit *g, cc_size l) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccdh_compute_shared_secret(ccdh_full_ctx_t ctx, ccdh_pub_ctx_t pub, size_t* len, const void* key, struct ccrng_state* rng) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return -1;
};

CC_CONST CC_NONNULL_TU((1))
const cc_unit *ccdh_gp_prime(ccdh_const_gp_t gp) {
    return cczp_prime(CCDH_CONST_GP_T_ZP(gp));
}

CC_CONST CC_NONNULL_TU((1))
size_t ccdh_ccn_size(ccdh_const_gp_t gp) {
    return ccn_sizeof_n(cczp_n(CCDH_CONST_GP_T_ZP(gp)));
}

CC_CONST CC_NONNULL_TU((1))
const cc_unit *ccdh_gp_g(ccdh_const_gp_t gp) {
#if CORECRYPTO_USE_TRANSPARENT_UNION
    return CCDH_GP_G(gp._ncgp);
#else
    return CCDH_GP_G((ccdh_gp_t)gp);
#endif
}

CC_CONST CC_NONNULL_TU((1))
cc_size ccdh_gp_n(ccdh_const_gp_t gp) {
    return cczp_n(CCDH_CONST_GP_T_ZP(gp));
}
