#include <ctest.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccmd5.h>
#include "test_data.h"

#define DIGEST_TEST(algorithm) \
	CTEST(ccdigest, ccdigest_ ## algorithm) { \
		const struct ccdigest_info* digest_info = cc ## algorithm ## _di(); \
		uint8_t hash[digest_info->output_size]; \
		ccdigest_di_decl(digest_info, ctx); \
		ccdigest_init(digest_info, ctx); \
		ccdigest_update(digest_info, ctx, sizeof(ccdigest_input_data), ccdigest_input_data); \
		ccdigest_final(digest_info, ctx, hash); \
		ASSERT_DATA(ccdigest_ ## algorithm ## _hash, sizeof(ccdigest_ ## algorithm ## _hash), hash, sizeof(hash)); \
	};

DIGEST_TEST(sha1);
DIGEST_TEST(sha224);
DIGEST_TEST(sha256);
DIGEST_TEST(sha384);
DIGEST_TEST(sha512);
DIGEST_TEST(md5);
