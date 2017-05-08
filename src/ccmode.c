#include <corecrypto/ccmode.h>

int ccgcm_one_shot(const struct ccmode_gcm *mode,
                             size_t key_len, const void *key,
                             size_t iv_len, const void *iv,
                             size_t adata_len, const void *adata,
                             size_t nbytes, const void *in, void *out,
                             size_t tag_len, void *tag) {
}

//do not call ccgcm_one_shot_legacy() in any new application
int ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
                           size_t key_len, const void *key,
                           size_t iv_len, const void *iv,
                           size_t adata_len, const void *adata,
                           size_t nbytes, const void *in, void *out,
                           size_t tag_len, void *tag) {
}

int ccgcm_init_with_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx,
                       size_t key_nbytes, const void *key,
                       const void *iv) {
}

int ccgcm_inc_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, void *iv) {
}

int ccgcm_set_iv_legacy(const struct ccmode_gcm *arg0, ccgcm_ctx *arg1, int c, const void *data) {
}
