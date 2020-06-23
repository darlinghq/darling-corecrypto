#include <corecrypto/private/ccgcm.h>
#include <string.h>

// `input` is assumed to be in normal byte order (big-endian; most significant byte at lowest address)
ccaes_block_128_t ccgcm_ghash_128(const ccaes_block_128_t hash_subkey, const size_t input_len, const uint8_t* const input) {
	const size_t m = (input_len + 15) / 16;
	ccaes_block_128_t y = {0};

	for (size_t i = 0; i < m; ++i) {
		const ccaes_block_128_t x = ccaes_normalize_128(input_len - (i * 16), input + (i * 16));
		y = ccaes_multiply_128(ccaes_xor_128(y, x), hash_subkey);
	}

	return y;
};

// `input` is assumed to be in normal byte order (big-endian; most significant byte at lowest address)
// `output` is in the same order as `input`
int ccgcm_gctr_128(const ccaes_block_cipher_function_t block_cipher_function, const size_t key_len, const uint8_t* const key, const ccaes_block_128_t icb, const size_t input_len, const uint8_t* const input, uint8_t* const output) {
	if (input_len == 0)
		return 0;

	const size_t n = (input_len + 15) / 16;
	ccaes_block_128_t cb = icb;
	size_t current_len = input_len;
	const uint8_t* current_input = input;
	uint8_t* current_output = output;

	for (size_t i = 0; i < n - 1; ++i) {
		const ccaes_block_128_t x = ccaes_normalize_128(current_len, current_input);
		const ccaes_block_128_t y = ccaes_xor_128(x, block_cipher_function(cb, key_len, key));
		ccaes_write_block_128(y, current_len, current_output);

		cb = ccaes_increment_128(cb, 32);

		current_len -= 16;
		current_input += 16;
		current_output += 16;
	}

	const size_t final_block_bytes = input_len - ((n - 1) * 8);
	const ccaes_block_128_t final_block = ccaes_normalize_128(current_len, current_input);
	const ccaes_block_128_t final_y = ccaes_xor_128(final_block, ccaes_most_significant_bits_128(block_cipher_function(cb, key_len, key), final_block_bytes * 8));
	ccaes_write_block_128(final_y, current_len, current_output);

	return 0;
};

//
// ~~~actual AES-GCM implementation~~~
//

int ccgcm_internal_init(const struct ccmode_gcm* gcm, ccgcm_ctx* ctx, size_t key_len, const void* key) {
	ccgcm_state* state = (ccgcm_state*)ctx;

	// our block cipher function only accepts 128-bit, 192-bit, or 256-bit keys
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return -1;

	*state = (ccgcm_state) {0};

	state->decrypting = gcm->encdec == CCMODE_GCM_DECRYPTOR;
	state->mode = CCGCM_MODE_INITIALIZE;

	state->key = key;
	state->key_len = key_len;

	state->hash_subkey = ccaes_block_cipher((ccaes_block_128_t){0}, state->key_len, state->key);

	return 0;
};

void ccgcm_process_iv(ccgcm_state* state) {
	if (state->total_iv_length == 12) {
		// we only do this when IV is 12 bytes because the only time
		// the IV is incremented for reuse is when it's set through
		// `ccgcm_init_with_iv`
		for (size_t i = 0; i < 12; ++i)
			state->current_iv[i] = state->cache.block[15 - i];

		state->cache.block[0] = 1;
		state->initial_cb = state->cache;
	} else {
		if (state->total_iv_length % 16 != 0) {
			state->initial_cb = ccaes_multiply_128(ccaes_xor_128(state->initial_cb, state->cache), state->hash_subkey);
			state->cache = (ccaes_block_128_t) {0};
		}

		const size_t iv_bits = state->total_iv_length * 8;
		ccaes_block_128_t length_block = {0};

		for (size_t i = 0; i < sizeof(size_t); ++i)
			length_block.block[i] = (iv_bits >> (i * 8)) & 0xff;

		state->initial_cb = ccaes_multiply_128(ccaes_xor_128(state->initial_cb, length_block), state->hash_subkey);
	}

	state->cache = (ccaes_block_128_t) {0};

	state->cb = ccaes_increment_128(state->initial_cb, 32);
	state->processed_cb = ccaes_block_cipher(state->cb, state->key_len, state->key);
};

int ccgcm_internal_set_iv(ccgcm_ctx* ctx, size_t iv_size, const void* iv) {
	ccgcm_state* state = (ccgcm_state*)ctx;

	const uint8_t* iv_buf = iv;

	if (state->mode == CCGCM_MODE_INITIALIZE)
		state->mode = CCGCM_MODE_IV;

	if (state->mode != CCGCM_MODE_IV)
		return CCMODE_INVALID_CALL_SEQUENCE;

	for (size_t i = 0; i < iv_size; ++i) {
		const size_t current_block_index = 15 - (state->total_iv_length % 16);

		state->cache.block[current_block_index] = iv_buf[i];

		if (current_block_index == 0) {
			state->initial_cb = ccaes_multiply_128(ccaes_xor_128(state->initial_cb, state->cache), state->hash_subkey);
			state->cache = (ccaes_block_128_t) {0};
		}

		++state->total_iv_length;
	}

	return 0;
};

CC_INLINE
void ccgcm_process_aad(ccgcm_state* state) {
	if (state->total_aad_length % 16 != 0) {
		state->hash = ccaes_multiply_128(ccaes_xor_128(state->hash, state->cache), state->hash_subkey);
		state->cache = (ccaes_block_128_t) {0};
	}
};

int ccgcm_internal_gmac(ccgcm_ctx* ctx, size_t buf_len, const void* in) {
	ccgcm_state* state = (ccgcm_state*)ctx;

	const uint8_t* in_buf = in;

	if (state->mode == CCGCM_MODE_IV) {
		ccgcm_process_iv(state);
		state->mode = CCGCM_MODE_AAD;
	}

	if (state->mode != CCGCM_MODE_AAD)
		return CCMODE_INVALID_CALL_SEQUENCE;

	for (size_t i = 0; i < buf_len; ++i) {
		const size_t current_block_index = 15 - (state->total_aad_length % 16);

		state->cache.block[current_block_index] = in_buf[i];

		if (current_block_index == 0) {
			state->hash = ccaes_multiply_128(ccaes_xor_128(state->hash, state->cache), state->hash_subkey);
			state->cache = (ccaes_block_128_t) {0};
		}

		++state->total_aad_length;
	}

	return 0;
};

CC_INLINE
void ccgcm_process_ciphertext(ccgcm_state* state) {
	if (state->total_cipher_length % 16 != 0) {
		state->hash = ccaes_multiply_128(ccaes_xor_128(state->hash, state->cache), state->hash_subkey);
		state->cache = (ccaes_block_128_t) {0};
	}
};

int ccgcm_internal_gcm(ccgcm_ctx* ctx, size_t buf_len, const void* in, void* out) {
	ccgcm_state* state = (ccgcm_state*)ctx;

	const uint8_t* in_buf = in;
	uint8_t* out_buf = out;

	if (state->mode == CCGCM_MODE_IV) {
		ccgcm_process_iv(state);
		state->mode = CCGCM_MODE_AAD;
	}

	if (state->mode == CCGCM_MODE_AAD) {
		ccgcm_process_aad(state);
		state->mode = CCGCM_MODE_CIPHERTEXT;
	}

	if (state->mode != CCGCM_MODE_CIPHERTEXT)
		return CCMODE_INVALID_CALL_SEQUENCE;

	for (size_t i = 0; i < buf_len; ++i) {
		const size_t current_block_index = 15 - (state->total_cipher_length % 16);

		out_buf[i] = in_buf[i] ^ state->processed_cb.block[current_block_index];

		const uint8_t cipher_byte = state->decrypting ? in_buf[i] : out_buf[i];

		state->cache.block[current_block_index] = cipher_byte;

		if (current_block_index == 0) {
			state->hash = ccaes_multiply_128(ccaes_xor_128(state->hash, state->cache), state->hash_subkey);
			state->cache = (ccaes_block_128_t) {0};
		}

		++state->total_cipher_length;

		if (state->total_cipher_length % 16 == 0) {
			state->cb = ccaes_increment_128(state->cb, 32);
			state->processed_cb = ccaes_block_cipher(state->cb, state->key_len, state->key);
		}
	}

	return 0;
};

int ccgcm_internal_finalize(ccgcm_ctx* ctx, size_t tag_size, void* tag) {
	ccgcm_state* state = (ccgcm_state*)ctx;

	if (state->mode == CCGCM_MODE_IV) {
		ccgcm_process_iv(state);
		state->mode = CCGCM_MODE_AAD;
	}

	if (state->mode == CCGCM_MODE_AAD) {
		ccgcm_process_aad(state);
		state->mode = CCGCM_MODE_CIPHERTEXT;
	}

	if (state->mode == CCGCM_MODE_CIPHERTEXT) {
		ccgcm_process_ciphertext(state);
		state->mode = CCGCM_MODE_FINALIZE;
	}

	if (state->mode != CCGCM_MODE_FINALIZE)
		return CCMODE_INVALID_CALL_SEQUENCE;

	const size_t aad_bits = state->total_aad_length * 8;
	const size_t cipher_bits = state->total_cipher_length * 8;

	uint8_t* tag_buf = tag;

	ccaes_block_128_t length_block = {0};

	for (size_t i = 0; i < sizeof(size_t); ++i)
		length_block.block[8 + i] = (aad_bits >> (i * 8)) & 0xff;

	for (size_t i = 0; i < sizeof(size_t); ++i)
		length_block.block[i] = (cipher_bits >> (i * 8)) & 0xff;

	state->hash = ccaes_multiply_128(ccaes_xor_128(state->hash, length_block), state->hash_subkey);

	const uint8_t hash_buf[16] = {
		state->hash.block[15],
		state->hash.block[14],
		state->hash.block[13],
		state->hash.block[12],
		state->hash.block[11],
		state->hash.block[10],
		state->hash.block[ 9],
		state->hash.block[ 8],
		state->hash.block[ 7],
		state->hash.block[ 6],
		state->hash.block[ 5],
		state->hash.block[ 4],
		state->hash.block[ 3],
		state->hash.block[ 2],
		state->hash.block[ 1],
		state->hash.block[ 0],
	};

	uint8_t result_buf[16] = {0};

	ccgcm_gctr_128(ccaes_block_cipher, state->key_len, state->key, state->initial_cb, sizeof hash_buf, hash_buf, result_buf);

	for (size_t i = 0; i < 16 && i < tag_size; ++i)
		tag_buf[i] = result_buf[i];

	return 0;
};

int ccgcm_internal_reset(ccgcm_ctx* ctx) {
	ccgcm_state* state = (ccgcm_state*)ctx;

	ccgcm_state new_state = {
		.decrypting = state->decrypting,
		.mode = CCGCM_MODE_INITIALIZE,
		.key_len = state->key_len,
		.key = state->key,
		// aggregate initialization automatically zeroes all other members
	};

	memcpy(new_state.current_iv, state->current_iv, sizeof state->current_iv);
	memcpy(new_state.hash_subkey.block, state->hash_subkey.block, sizeof state->hash_subkey);

	*state = new_state;

	return 0;
};
