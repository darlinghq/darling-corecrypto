#include <ctest.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/private/cc128.h>
#include <stdio.h>
#include "test_data.h"

#define ECB_TESTS(des_name, key_bits) \
	CTEST(ccdes, ccdes_ ## key_bits ## _ecb_encrypt) { \
		const struct ccmode_ecb* ecb = cc ## des_name ## _ecb_encrypt_mode(); \
		ccecb_ctx_decl(ecb->size, ctx); \
		uint8_t ciphertext[sizeof(ccdes_ ## key_bits ## _ecb_ciphertext)]; \
		ASSERT_EQUAL(CCERR_OK, ccecb_init(ecb, ctx, sizeof(ccdes_ ## key_bits ## _key), ccdes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, ccecb_update(ecb, ctx, sizeof(ccdes_plaintext_block) / ecb->block_size, ccdes_plaintext_block, ciphertext)); \
		ASSERT_DATA(ccdes_ ## key_bits ## _ecb_ciphertext, sizeof(ccdes_ ## key_bits ## _ecb_ciphertext), ciphertext, sizeof(ciphertext)); \
	}; \
	CTEST(ccdes, ccdes_ ## key_bits ## _ecb_decrypt) { \
		const struct ccmode_ecb* ecb = cc ## des_name ## _ecb_decrypt_mode(); \
		ccecb_ctx_decl(ecb->size, ctx); \
		uint8_t plaintext[sizeof(ccdes_plaintext_block)]; \
		ASSERT_EQUAL(CCERR_OK, ccecb_init(ecb, ctx, sizeof(ccdes_ ## key_bits ## _key), ccdes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, ccecb_update(ecb, ctx, sizeof(ccdes_ ## key_bits ## _ecb_ciphertext) / ecb->block_size, ccdes_ ## key_bits ## _ecb_ciphertext, plaintext)); \
		ASSERT_DATA(ccdes_plaintext_block, sizeof(ccdes_plaintext_block), plaintext, sizeof(plaintext)); \
	};

ECB_TESTS(des, 64);
ECB_TESTS(des3, 128);
ECB_TESTS(des3, 192);

#define CBC_TESTS(des_name, key_bits) \
	CTEST(ccdes, ccdes_ ## key_bits ## _cbc_encrypt) { \
		const struct ccmode_cbc* cbc = cc ## des_name ## _cbc_encrypt_mode(); \
		cccbc_ctx_decl(cbc->size, ctx); \
		cccbc_iv_decl(cbc->block_size, iv); \
		uint8_t ciphertext[sizeof(ccdes_ ## key_bits ## _cbc_ciphertext)]; \
		ASSERT_EQUAL(CCERR_OK, cccbc_init(cbc, ctx, sizeof(ccdes_ ## key_bits ## _key), ccdes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_set_iv(cbc, iv, ccdes_ ## key_bits ## _cbc_iv)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_update(cbc, ctx, iv, sizeof(ccdes_plaintext_block) / cbc->block_size, ccdes_plaintext_block, ciphertext)); \
		ASSERT_DATA(ccdes_ ## key_bits ## _cbc_ciphertext, sizeof(ccdes_ ## key_bits ## _cbc_ciphertext), ciphertext, sizeof(ciphertext)); \
	}; \
	CTEST(ccdes, ccdes_ ## key_bits ## _cbc_decrypt) { \
		const struct ccmode_cbc* cbc = cc ## des_name ## _cbc_decrypt_mode(); \
		cccbc_ctx_decl(cbc->size, ctx); \
		cccbc_iv_decl(cbc->block_size, iv); \
		uint8_t plaintext[sizeof(ccdes_plaintext_block)]; \
		ASSERT_EQUAL(CCERR_OK, cccbc_init(cbc, ctx, sizeof(ccdes_ ## key_bits ## _key), ccdes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_set_iv(cbc, iv, ccdes_ ## key_bits ## _cbc_iv)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_update(cbc, ctx, iv, sizeof(ccdes_ ## key_bits ## _cbc_ciphertext) / cbc->block_size, ccdes_ ## key_bits ## _cbc_ciphertext, plaintext)); \
		ASSERT_DATA(ccdes_plaintext_block, sizeof(ccdes_plaintext_block), plaintext, sizeof(plaintext)); \
	};

CBC_TESTS(des, 64);
CBC_TESTS(des3, 128);
CBC_TESTS(des3, 192);
