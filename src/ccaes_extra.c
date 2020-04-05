#include <corecrypto/private/ccaes_extra.h>
#include <string.h>

CC_INLINE
int ccaes_expand_key(const size_t key_len, const uint8_t* const key, ccaes_word_t* const expanded_keys) {
	const size_t Nr = ccaes_round_count(key_len);
	const size_t Nk = key_len / 4;
	ccaes_word_t tmp = {0};

	for (size_t i = 0; i < Nk; ++i)
		expanded_keys[i] = (ccaes_word_t) { .bytes = { key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3], }, };

	for (size_t i = Nk; i < 4 * (Nr + 1); ++i) {
		tmp = expanded_keys[i - 1];

		if (i % Nk == 0) {
			tmp = ccaes_rot_word(tmp);
			ccaes_sub_bytes(4, tmp.bytes, tmp.bytes);
			tmp.bytes[0] ^= ccaes_round_constant[(i / Nk) - 1];
		} else if (Nk > 6 && i % Nk == 4) {
			ccaes_sub_bytes(4, tmp.bytes, tmp.bytes);
		}

		expanded_keys[i] = ccaes_xor_word(expanded_keys[i - Nk], tmp);
	}

	return 0;
};

ccaes_block_128_t ccaes_block_cipher(const ccaes_block_128_t input, const size_t key_len, const uint8_t* const key) {
	if (key_len != 16 && key_len != 24 && key_len != 32)
		return (ccaes_block_128_t) {0};

	const size_t Nr = ccaes_round_count(key_len);

	ccaes_word_t expanded_keys[4 * (Nr + 1)];
	memset(expanded_keys, 0, sizeof expanded_keys);

	ccaes_expand_key(key_len, key, expanded_keys);

	ccaes_state_t state = {
		.bytes = {
			{ input.block[15], input.block[11], input.block[ 7], input.block[ 3], },
			{ input.block[14], input.block[10], input.block[ 6], input.block[ 2], },
			{ input.block[13], input.block[ 9], input.block[ 5], input.block[ 1], },
			{ input.block[12], input.block[ 8], input.block[ 4], input.block[ 0], },
		},
	};

	state = ccaes_add_round_key(state, &expanded_keys[0]);

	for (size_t round = 1; round < Nr; ++round) {
		ccaes_sub_bytes(16, (const uint8_t*)state.bytes, (uint8_t*)state.bytes);
		state = ccaes_shift_rows(state);
		state = ccaes_mix_columns(state);
		state = ccaes_add_round_key(state, &expanded_keys[4 * round]);
	}

	ccaes_sub_bytes(16, (const uint8_t*)state.bytes, (uint8_t*)state.bytes);
	state = ccaes_shift_rows(state);
	state = ccaes_add_round_key(state, &expanded_keys[4 * Nr]);

	return (ccaes_block_128_t) {
		.block = {
			state.bytes[3][3],
			state.bytes[2][3],
			state.bytes[1][3],
			state.bytes[0][3],

			state.bytes[3][2],
			state.bytes[2][2],
			state.bytes[1][2],
			state.bytes[0][2],

			state.bytes[3][1],
			state.bytes[2][1],
			state.bytes[1][1],
			state.bytes[0][1],

			state.bytes[3][0],
			state.bytes[2][0],
			state.bytes[1][0],
			state.bytes[0][0],
		},
	};
};
