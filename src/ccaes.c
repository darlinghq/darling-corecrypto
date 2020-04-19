#include <corecrypto/ccaes.h>
#include <corecrypto/private/ccgcm.h>
#include <stdio.h>

static const struct ccmode_gcm ccaes_gcm_encrypt = {
	.size = sizeof(ccgcm_state),
	.encdec = CCMODE_GCM_ENCRYPTOR,
	.block_size = 16,
	.init = ccgcm_internal_init,
	.set_iv = ccgcm_internal_set_iv,
	.gmac = ccgcm_internal_gmac,
	.gcm = ccgcm_internal_gcm,
	.finalize = ccgcm_internal_finalize,
	.reset = ccgcm_internal_reset,
	.custom = NULL,
};

static const struct ccmode_gcm ccaes_gcm_decrypt = {
	.size = sizeof(ccgcm_state),
	.encdec = CCMODE_GCM_DECRYPTOR,
	.block_size = 16,
	.init = ccgcm_internal_init,
	.set_iv = ccgcm_internal_set_iv,
	.gmac = ccgcm_internal_gmac,
	.gcm = ccgcm_internal_gcm,
	.finalize = ccgcm_internal_finalize,
	.reset = ccgcm_internal_reset,
	.custom = NULL,
};

const struct ccmode_ecb *ccaes_ecb_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_cbc *ccaes_cbc_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_cfb *ccaes_cfb_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_cfb8 *ccaes_cfb8_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_xts *ccaes_xts_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_gcm* ccaes_gcm_encrypt_mode(void) {
	return &ccaes_gcm_encrypt;
};

const struct ccmode_ccm *ccaes_ccm_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_ecb *ccaes_ecb_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_cbc *ccaes_cbc_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_cfb *ccaes_cfb_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_cfb8 *ccaes_cfb8_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_xts *ccaes_xts_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_gcm* ccaes_gcm_decrypt_mode(void) {
	return &ccaes_gcm_decrypt;
};

const struct ccmode_ccm *ccaes_ccm_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_ctr *ccaes_ctr_crypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_ofb *ccaes_ofb_crypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_siv *ccaes_siv_encrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const struct ccmode_siv *ccaes_siv_decrypt_mode(void) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

