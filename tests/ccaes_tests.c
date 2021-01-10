#include <ctest.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/cc_debug.h>
#include <corecrypto/private/cc128.h>
#include <stdio.h>
#include "test_data.h"

#define ECB_TESTS(key_bits) \
	CTEST(ccaes, ccaes_ ## key_bits ## _ecb_encrypt) { \
		const struct ccmode_ecb* ecb = ccaes_ecb_encrypt_mode(); \
		ccecb_ctx_decl(ecb->size, ctx); \
		uint8_t ciphertext[sizeof(ccaes_ ## key_bits ## _ecb_ciphertext)]; \
		ASSERT_EQUAL(CCERR_OK, ccecb_init(ecb, ctx, sizeof(ccaes_ ## key_bits ## _key), ccaes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, ccecb_update(ecb, ctx, sizeof(ccaes_plaintext_block) / ecb->block_size, ccaes_plaintext_block, ciphertext)); \
		ASSERT_DATA(ccaes_ ## key_bits ## _ecb_ciphertext, sizeof(ccaes_ ## key_bits ## _ecb_ciphertext), ciphertext, sizeof(ciphertext)); \
	}; \
	CTEST(ccaes, ccaes_ ## key_bits ## _ecb_decrypt) { \
		const struct ccmode_ecb* ecb = ccaes_ecb_decrypt_mode(); \
		ccecb_ctx_decl(ecb->size, ctx); \
		uint8_t plaintext[sizeof(ccaes_plaintext_block)]; \
		ASSERT_EQUAL(CCERR_OK, ccecb_init(ecb, ctx, sizeof(ccaes_ ## key_bits ## _key), ccaes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, ccecb_update(ecb, ctx, sizeof(ccaes_ ## key_bits ## _ecb_ciphertext) / ecb->block_size, ccaes_ ## key_bits ## _ecb_ciphertext, plaintext)); \
		ASSERT_DATA(ccaes_plaintext_block, sizeof(ccaes_plaintext_block), plaintext, sizeof(plaintext)); \
	};

ECB_TESTS(128);
ECB_TESTS(192);
ECB_TESTS(256);

#define CBC_TESTS(key_bits) \
	CTEST(ccaes, ccaes_ ## key_bits ## _cbc_encrypt) { \
		const struct ccmode_cbc* cbc = ccaes_cbc_encrypt_mode(); \
		cccbc_ctx_decl(cbc->size, ctx); \
		cccbc_iv_decl(cbc->block_size, iv); \
		uint8_t ciphertext[sizeof(ccaes_ ## key_bits ## _cbc_ciphertext)]; \
		ASSERT_EQUAL(CCERR_OK, cccbc_init(cbc, ctx, sizeof(ccaes_ ## key_bits ## _key), ccaes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_set_iv(cbc, iv, ccaes_ ## key_bits ## _cbc_iv)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_update(cbc, ctx, iv, sizeof(ccaes_plaintext_block) / cbc->block_size, ccaes_plaintext_block, ciphertext)); \
		ASSERT_DATA(ccaes_ ## key_bits ## _cbc_ciphertext, sizeof(ccaes_ ## key_bits ## _cbc_ciphertext), ciphertext, sizeof(ciphertext)); \
	}; \
	CTEST(ccaes, ccaes_ ## key_bits ## _cbc_decrypt) { \
		const struct ccmode_cbc* cbc = ccaes_cbc_decrypt_mode(); \
		cccbc_ctx_decl(cbc->size, ctx); \
		cccbc_iv_decl(cbc->block_size, iv); \
		uint8_t plaintext[sizeof(ccaes_plaintext_block)]; \
		ASSERT_EQUAL(CCERR_OK, cccbc_init(cbc, ctx, sizeof(ccaes_ ## key_bits ## _key), ccaes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_set_iv(cbc, iv, ccaes_ ## key_bits ## _cbc_iv)); \
		ASSERT_EQUAL(CCERR_OK, cccbc_update(cbc, ctx, iv, sizeof(ccaes_ ## key_bits ## _cbc_ciphertext) / cbc->block_size, ccaes_ ## key_bits ## _cbc_ciphertext, plaintext)); \
		ASSERT_DATA(ccaes_plaintext_block, sizeof(ccaes_plaintext_block), plaintext, sizeof(plaintext)); \
	};

CBC_TESTS(128);
CBC_TESTS(192);
CBC_TESTS(256);

#define GCM_TESTS(key_bits) \
	CTEST(ccaes, ccaes_ ## key_bits ## _gcm_encrypt) { \
		const struct ccmode_gcm* gcm = ccaes_gcm_encrypt_mode(); \
		ccgcm_ctx_decl(gcm->size, ctx); \
		uint8_t ciphertext[sizeof(ccaes_ ## key_bits ## _gcm_ciphertext)]; \
		uint8_t tag[sizeof(ccaes_ ## key_bits ## _gcm_tag)]; \
		ASSERT_EQUAL(CCERR_OK, ccgcm_init(gcm, ctx, sizeof(ccaes_ ## key_bits ## _key), ccaes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_set_iv(gcm, ctx, sizeof(ccaes_ ## key_bits ## _gcm_iv), ccaes_ ## key_bits ## _gcm_iv)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_update(gcm, ctx, sizeof(ccaes_plaintext_block), ccaes_plaintext_block, ciphertext)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_finalize(gcm, ctx, sizeof(tag), tag)); \
		ASSERT_DATA(ccaes_ ## key_bits ## _gcm_ciphertext, sizeof(ccaes_ ## key_bits ## _gcm_ciphertext), ciphertext, sizeof(ciphertext)); \
		/*ASSERT_DATA(ccaes_ ## key_bits ## _gcm_tag, sizeof(ccaes_ ## key_bits ## _gcm_tag), tag, sizeof(tag));*/ \
	}; \
	CTEST(ccaes, ccaes_ ## key_bits ## _gcm_decrypt) { \
		const struct ccmode_gcm* gcm = ccaes_gcm_decrypt_mode(); \
		ccgcm_ctx_decl(gcm->size, ctx); \
		uint8_t plaintext[sizeof(ccaes_plaintext_block)]; \
		uint8_t tag[sizeof(ccaes_ ## key_bits ## _gcm_tag)]; \
		memcpy(tag, ccaes_ ## key_bits ## _gcm_tag, sizeof(tag)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_init(gcm, ctx, sizeof(ccaes_ ## key_bits ## _key), ccaes_ ## key_bits ## _key)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_set_iv(gcm, ctx, sizeof(ccaes_ ## key_bits ## _gcm_iv), ccaes_ ## key_bits ## _gcm_iv)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_update(gcm, ctx, sizeof(ccaes_ ## key_bits ## _gcm_ciphertext), ccaes_ ## key_bits ## _gcm_ciphertext, plaintext)); \
		ASSERT_EQUAL(CCERR_OK, ccgcm_finalize(gcm, ctx, sizeof(tag), tag)); \
		ASSERT_DATA(ccaes_plaintext_block, sizeof(ccaes_plaintext_block), plaintext, sizeof(plaintext)); \
		/*ASSERT_DATA(ccaes_ ## key_bits ## _gcm_tag, sizeof(ccaes_ ## key_bits ## _gcm_tag), tag, sizeof(tag));*/ \
	};

GCM_TESTS(128);
GCM_TESTS(192);
GCM_TESTS(256);
