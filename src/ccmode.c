#include <corecrypto/ccmode.h>
#include <corecrypto/private/ccgcm.h>
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

int ccgcm_init_with_iv(const struct ccmode_gcm* mode, ccgcm_ctx* ctx, size_t key_nbytes, const void* key, const void* iv) {
	ccgcm_init(mode, ctx, key_nbytes, key);
	ccgcm_set_iv(mode, ctx, 12, iv);
	return 0;
};

int ccgcm_inc_iv(const struct ccmode_gcm* mode, ccgcm_ctx* ctx, void* iv) {
	uint8_t* iv_buf = iv;
	ccgcm_state* state = (ccgcm_state*)ctx;

	state->cache = (ccaes_block_128_t) {0};

	for (size_t i = 0; i < 12; ++i)
		state->cache.block[15 - i] = state->current_iv[i];

	for (size_t i = 0; i < 8; ++i) {
		state->cache.block[4 + i] += 1;
		if (state->cache.block[4 + i] != 0)
			break;
	}

	state->total_iv_length = 12;

	ccgcm_process_iv(state);

	memcpy(iv_buf, state->current_iv, 12);

	return 0;
};

int ccgcm_set_iv_legacy(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t iv_nbytes, const void *iv) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
};
