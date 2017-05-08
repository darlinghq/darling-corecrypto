#include <corecrypto/cchmac.h>

void cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t ctx,
                 size_t key_len, const void *key) {
}

void cchmac_update(const struct ccdigest_info *di, cchmac_ctx_t ctx,
                   size_t data_len, const void *data) {
}

void cchmac_final(const struct ccdigest_info *di, cchmac_ctx_t ctx,
                  unsigned char *mac) {
}

void cchmac(const struct ccdigest_info *di, size_t key_len,
            const void *key, size_t data_len, const void *data,
            unsigned char *mac) {
	return 0;
}

int cchmac_test(const struct cchmac_test_input *input);
int cchmac_test_chunks(const struct cchmac_test_input *input, size_t chunk_size) {
	return 0;
}
