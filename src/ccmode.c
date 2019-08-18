#include <corecrypto/ccmode.h>
#include <stdio.h>

int ccgcm_one_shot(const struct ccmode_gcm *mode,
                             size_t key_len, const void *key,
                             size_t iv_len, const void *iv,
                             size_t adata_len, const void *adata,
                             size_t nbytes, const void *in, void *out,
                             size_t tag_len, void *tag) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
                           size_t key_len, const void *key,
                           size_t iv_len, const void *iv,
                           size_t adata_len, const void *adata,
                           size_t nbytes, const void *in, void *out,
                           size_t tag_len, void *tag) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                       size_t key_nbytes, const void *key,
                       const void *iv) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccgcm_inc_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, void *iv) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccgcm_set_iv_legacy(const struct ccmode_gcm *arg0, ccgcm_ctx *arg1, int c, const void *data) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
