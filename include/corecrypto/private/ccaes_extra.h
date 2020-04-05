#ifndef CC_PRIVATE_CCAES_EXTRA_H
#define CC_PRIVATE_CCAES_EXTRA_H

#include <corecrypto/cc.h>
#include <stdbool.h>

//
// ~~~typedefs~~~
//

// little endian representation of a 128-bit block
typedef struct {
	uint8_t block[16];
} ccaes_block_128_t;

typedef struct {
	uint8_t bytes[4][4];
} ccaes_state_t;

typedef struct {
	uint8_t bytes[4];
} ccaes_word_t;

// `key` is a big-endian array
typedef ccaes_block_128_t (*ccaes_block_cipher_function_t)(const ccaes_block_128_t input, const size_t key_len, const uint8_t* const key);

//
// ~~~constants~~~
//

static const uint8_t ccaes_s_box[16][16] = {
	{ 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, },
	{ 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, },
	{ 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, },
	{ 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, },
	{ 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, },
	{ 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, },
	{ 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, },
	{ 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, },
	{ 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, },
	{ 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, },
	{ 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, },
	{ 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, },
	{ 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, },
	{ 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, },
	{ 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, },
	{ 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, },
};

static const uint8_t ccaes_round_constant[] = {
	0x01,
	0x02,
	0x04,
	0x08,
	0x10,
	0x20,
	0x40,
	0x80,
	0x1b,
	0x36,
};

//
// ~~~function declarations~~~
//

// `key` is a big-endian array
ccaes_block_128_t ccaes_block_cipher(const ccaes_block_128_t input, const size_t key_len, const uint8_t* const key);

//
// ~~~inline functions~~~
//

CC_INLINE
void ccaes_sub_bytes(const size_t len, const uint8_t* const in, uint8_t* const out) {
	for (size_t i = 0; i < len; ++i)
		out[i] = ccaes_s_box[(in[i] & 0xf0) >> 4][in[i] & 0x0f];
};

CC_INLINE
ccaes_state_t ccaes_shift_rows(const ccaes_state_t state) {
	return (ccaes_state_t) {
		.bytes = {
			{ state.bytes[0][0], state.bytes[0][1], state.bytes[0][2], state.bytes[0][3], },
			{ state.bytes[1][1], state.bytes[1][2], state.bytes[1][3], state.bytes[1][0], },
			{ state.bytes[2][2], state.bytes[2][3], state.bytes[2][0], state.bytes[2][1], },
			{ state.bytes[3][3], state.bytes[3][0], state.bytes[3][1], state.bytes[3][2], },
		},
	};
};

CC_INLINE
ccaes_state_t ccaes_mix_columns(const ccaes_state_t state) {
	// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example

	ccaes_state_t result = {0};

	// hopefully the compiler is smart enough to unroll this loop
	for (uint8_t i = 0; i < 4; ++i) {
		uint8_t b[4] = {0};

		for (uint8_t j = 0; j < 4; ++j) {
			uint8_t h = state.bytes[j][i] & 0x80;
			b[j] = state.bytes[j][i] << 1;
			if (h)
				b[j] ^= 0x1b;
		}

		result.bytes[0][i] = b[0] ^ state.bytes[3][i] ^ state.bytes[2][i] ^ b[1] ^ state.bytes[1][i];
		result.bytes[1][i] = b[1] ^ state.bytes[0][i] ^ state.bytes[3][i] ^ b[2] ^ state.bytes[2][i];
		result.bytes[2][i] = b[2] ^ state.bytes[1][i] ^ state.bytes[0][i] ^ b[3] ^ state.bytes[3][i];
		result.bytes[3][i] = b[3] ^ state.bytes[2][i] ^ state.bytes[1][i] ^ b[0] ^ state.bytes[0][i];
	}

	return result;
};

CC_INLINE
ccaes_state_t ccaes_add_round_key(const ccaes_state_t state, const ccaes_word_t* const round_key) {
	return (ccaes_state_t) {
		.bytes = {
			{ (state.bytes[0][0] ^ round_key[0].bytes[0]), (state.bytes[0][1] ^ round_key[1].bytes[0]), (state.bytes[0][2] ^ round_key[2].bytes[0]), (state.bytes[0][3] ^ round_key[3].bytes[0]), },
			{ (state.bytes[1][0] ^ round_key[0].bytes[1]), (state.bytes[1][1] ^ round_key[1].bytes[1]), (state.bytes[1][2] ^ round_key[2].bytes[1]), (state.bytes[1][3] ^ round_key[3].bytes[1]), },
			{ (state.bytes[2][0] ^ round_key[0].bytes[2]), (state.bytes[2][1] ^ round_key[1].bytes[2]), (state.bytes[2][2] ^ round_key[2].bytes[2]), (state.bytes[2][3] ^ round_key[3].bytes[2]), },
			{ (state.bytes[3][0] ^ round_key[0].bytes[3]), (state.bytes[3][1] ^ round_key[1].bytes[3]), (state.bytes[3][2] ^ round_key[2].bytes[3]), (state.bytes[3][3] ^ round_key[3].bytes[3]), },
		},
	};
};

CC_INLINE
ccaes_state_t ccaes_read_state(const size_t len, const uint8_t* const data) {
	ccaes_state_t result = {0};

	for (size_t i = 0; i < len && i < 16; ++i)
		result.bytes[i / 4][i % 4] = data[i];

	return result;
};

CC_INLINE
void ccaes_write_state(const ccaes_state_t state, const size_t len, uint8_t* const out) {
	for (size_t i = 0; i < len && i < 16; ++i)
		out[i] = state.bytes[i / 4][i % 4];
};

CC_INLINE
void ccaes_read_column(ccaes_state_t* const state, const size_t column, const uint8_t* const data) {
	for (size_t i = 0; i < 4; ++i)
		state->bytes[i][column] = data[i];
};

CC_INLINE
void ccaes_write_column(const ccaes_state_t state, const size_t column, uint8_t* const out) {
	for (size_t i = 0; i < 4; ++i)
		out[i] = state.bytes[i][column];
};

CC_INLINE
size_t ccaes_round_count(const size_t key_len) {
	if (key_len == 16)
		return 10;
	if (key_len == 24)
		return 12;
	if (key_len == 32)
		return 14;
	return 0;
};

CC_INLINE
ccaes_word_t ccaes_rot_word(const ccaes_word_t word) {
	return (ccaes_word_t) {
		.bytes = { word.bytes[1], word.bytes[2], word.bytes[3], word.bytes[0] },
	};
};

CC_INLINE
ccaes_word_t ccaes_xor_word(const ccaes_word_t x, const ccaes_word_t y) {
	return (ccaes_word_t) {
		.bytes = { x.bytes[0] ^ y.bytes[0], x.bytes[1] ^ y.bytes[1], x.bytes[2] ^ y.bytes[2], x.bytes[3] ^ y.bytes[3] },
	};
};

// get the bit at the specified 0-based index
CC_INLINE
bool ccaes_bit_128(const ccaes_block_128_t block, const uint8_t index) {
	return (block.block[index / 8] >> (index % 8)) & 1;
};

CC_INLINE
ccaes_block_128_t ccaes_xor_128(const ccaes_block_128_t x, const ccaes_block_128_t y) {
	return (ccaes_block_128_t) {
		.block = {
			x.block[ 0] ^ y.block[ 0],
			x.block[ 1] ^ y.block[ 1],
			x.block[ 2] ^ y.block[ 2],
			x.block[ 3] ^ y.block[ 3],
			x.block[ 4] ^ y.block[ 4],
			x.block[ 5] ^ y.block[ 5],
			x.block[ 6] ^ y.block[ 6],
			x.block[ 7] ^ y.block[ 7],
			x.block[ 8] ^ y.block[ 8],
			x.block[ 9] ^ y.block[ 9],
			x.block[10] ^ y.block[10],
			x.block[11] ^ y.block[11],
			x.block[12] ^ y.block[12],
			x.block[13] ^ y.block[13],
			x.block[14] ^ y.block[14],
			x.block[15] ^ y.block[15],
		},
	};
};

// shift right by a single bit (i.e. `>> 1`)
CC_INLINE
ccaes_block_128_t ccaes_shift_right_128(const ccaes_block_128_t block) {
	ccaes_block_128_t result = {0};

	for (uint8_t i = 0; i < 15; ++i)
		result.block[i] = (block.block[i] >> 1) | ((block.block[i + 1] & 1) << 7);

	result.block[15] = block.block[15] >> 1;

	return result;
};

CC_INLINE
ccaes_block_128_t ccaes_most_significant_bits_128(const ccaes_block_128_t block, const uint8_t bits) {
	const uint8_t bytes = (bits + 7) / 8;
	ccaes_block_128_t result = {0};
	const uint8_t diff = 16 - bytes;

	for (uint8_t i = 0; i < bytes; ++i)
		result.block[i] = block.block[i + diff];

	const uint8_t final_byte_bits = bits % 8;
	result.block[bytes - 1] &= (0xff << (8 - final_byte_bits)) >> (8 - final_byte_bits);

	return result;
};

CC_INLINE
ccaes_block_128_t ccaes_least_significant_bits_128(const ccaes_block_128_t block, const uint8_t bits) {
	ccaes_block_128_t result = {0};
	const uint8_t bytes = (bits + 7) / 8;

	for (uint8_t i = 0; i < bytes; ++i)
		result.block[i] = block.block[i];

	const uint8_t final_byte_bits = bits % 8;
	result.block[bytes - 1] &= (0xff << (8 - final_byte_bits)) >> (8 - final_byte_bits);

	return result;
};

// increment the least significant `bits` number of bits of `block`
CC_INLINE
ccaes_block_128_t ccaes_increment_128(const ccaes_block_128_t block, const uint8_t bits) {
	ccaes_block_128_t result = block;
	const uint8_t bytes = (bits + 7) / 8;
	uint8_t carry = 1;

	for (uint8_t i = 0; i < bytes - 1; ++i) {
		const uint8_t sum = result.block[i] + carry;
		carry = (sum < result.block[i]) ? 1 : 0;
		result.block[i] = sum;
	}

	const uint8_t final_byte_bits = bits - ((bytes - 1) * 8);
	const uint8_t mask = (0xff << (8 - final_byte_bits)) >> (8 - final_byte_bits);

	result.block[bytes - 1] = (result.block[bytes - 1] & ~mask) | ((result.block[bytes - 1] + carry) & mask);

	return result;
};

CC_INLINE
ccaes_block_128_t ccaes_multiply_128(const ccaes_block_128_t x, const ccaes_block_128_t y) {
	ccaes_block_128_t z = {0};
	ccaes_block_128_t v = y;

	for (uint8_t i = 128; i > 0; --i) {
		if (ccaes_bit_128(x, i - 1))
			z = ccaes_xor_128(z, v);
		const bool lsb_v = ccaes_bit_128(v, 0);
		v = ccaes_shift_right_128(v);
		if (lsb_v)
			v.block[15] ^= 0xe1;
	}

	return z;
};

CC_INLINE
ccaes_block_128_t ccaes_power_128(const ccaes_block_128_t block, const size_t power) {
	if (power == 0) {
		return (ccaes_block_128_t) {
			.block = {
				1,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
				0,
			},
		};
	}

	ccaes_block_128_t result = block;

	for (size_t i = 0; i < power - 1; ++i)
		result = ccaes_multiply_128(result, block);

	return result;
};

// creates a 128-bit block from the leading bytes of `data`,
// regardless of whether `data` actually has 128-bits of data available
//
// (assumes that `data` is big-endian)
//
// this could actually be named `ccaes_read_block_128`
CC_INLINE
ccaes_block_128_t ccaes_normalize_128(const size_t len, const uint8_t* const data) {
	ccaes_block_128_t result = {0};

	for (size_t i = 0; i < len && i < 16; ++i)
		result.block[15 - i] = data[i];

	return result;
};

// writes the given block to the output array in big-endian byte order
CC_INLINE
void ccaes_write_block_128(ccaes_block_128_t block, const size_t out_len, uint8_t* const out) {
	for (size_t i = 0; i < out_len && i < 16; ++i)
		out[i] = block.block[15 - i];
};

#endif // CC_PRIVATE_CCAES_EXTRA_H
