/*
 * cczp_mod (Barrett reduction) against reductions computed independently in
 * Python, for the primes and group orders of P-256 and P-384 (FIPS 186-4
 * D.1.2; the values were taken from OpenSSL's explicit curve parameters).
 * P-521 is left out: its reciprocal constants in ccec.c are wrong, which is a
 * separate defect. Inputs per modulus m: 0, m - 1, m, m * m - 1, one random
 * value below m * m, and t * m + (m - 1) with t chosen so that the low k + 1
 * units of t * m lie within m of 2^(64 (k + 1)); that makes the subtraction in
 * step 3 of HAC 14.42 borrow, which random inputs do with probability ~2^-62.
 *
 * Build and run from the repository root on an x86_64 host (on an aarch64
 * Linux host add -D__arm64__ so cc_unit is 64-bit). A hang is a failure:
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/cczp_mod_vectors.c \
 *     -o /tmp/cczp_mod_vectors && timeout 60 /tmp/cczp_mod_vectors
 */
#include <corecrypto/ccec.h>
#include <corecrypto/cczp.h>
#include <corecrypto/private/ccec_extra.h>
#include <stdio.h>
#include <string.h>

static const struct {
	unsigned curve;
	char modulus; /* 'p' prime, 'n' order */
	unsigned n;
	unsigned long long x[12], expected[6];
} vectors[] = {
	{ 256, 'p', 4,
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 256, 'p', 4,
	  {0xfffffffffffffffe, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0xfffffffffffffffe, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001} },
	{ 256, 'p', 4,
	  {0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 256, 'p', 4,
	  {0x0000000000000000, 0xfffffffe00000000, 0xffffffffffffffff, 0x00000001fffffffe, 0x00000001fffffffe, 0x00000001fffffffe, 0xfffffffe00000001, 0xfffffffe00000002},
	  {0xfffffffffffffffe, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001} },
	{ 256, 'p', 4,
	  {0x9daa37e51b591d75, 0xc15521b1b3dca50a, 0x86f0ce2ea6ec39c1, 0x3f372617f0baef3a, 0xbc3199944567ceb1, 0x4a800646417a8105, 0x12979bfcbbeb508f, 0x732242fda8902e32},
	  {0xb120f4c35b5f64b7, 0x6c07c015118d1f29, 0xe4681e3deed62671, 0x838849ebe1ae3382} },
	{ 256, 'n', 4,
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 256, 'n', 4,
	  {0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000} },
	{ 256, 'n', 4,
	  {0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 256, 'n', 4,
	  {0xab0dbaa15a1683a0, 0x32ad5e5de469c27b, 0x9a02fcd85d724aa1, 0x0043661f1d819d01, 0x13124dd75f81f226, 0x79cdf55bd46147ae, 0xfffffffe00000000, 0xfffffffe00000002},
	  {0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000} },
	{ 256, 'n', 4,
	  {0x77744cca4d909eb2, 0xdf7142dcaf29e6f8, 0x64d0b50f658c6762, 0xe8af30f7c70b53bf, 0x4375d0341e4f6f2a, 0xdeeda8b23927f7d6, 0x50cef798e6c648e7, 0xcecf4f4e5ba80780},
	  {0x83dc793460548659, 0x456c30bcaacce9b2, 0x0a704c8c06cc30c4, 0x20657c01213284df} },
	{ 384, 'p', 6,
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 384, 'p', 6,
	  {0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff} },
	{ 384, 'p', 6,
	  {0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 384, 'p', 6,
	  {0xfffffffe00000000, 0x0000000200000000, 0xfffffffe00000000, 0x0000000200000000, 0x0000000000000001, 0x0000000000000000, 0x00000001fffffffe, 0xfffffffe00000000, 0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
	  {0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff} },
	{ 384, 'p', 6,
	  {0x5c54e05b42a9ba21, 0xa1fa7d4acde560db, 0x842a2f9da1b4ba07, 0x293a9acc2652f8ff, 0xaa59c1698d242349, 0x467c0714a9fbd797, 0x02b7075d2a3a0c78, 0x11e760a5a6d5b30a, 0x98466a921f7ea79c, 0x071d14815649f8e9, 0x46287225154d1eb0, 0xdaa4ed3c3454fae4},
	  {0x2e7ea4aeedb46a33, 0x83c1e015068087a0, 0x2ff60222fce63839, 0xe618abe386b27064, 0xc9c5785a53193fa6, 0x09362c9df58f6dc1} },
	{ 384, 'n', 6,
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 384, 'n', 6,
	  {0xecec196accc52972, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0xecec196accc52972, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff} },
	{ 384, 'n', 6,
	  {0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000} },
	{ 384, 'n', 6,
	  {0x2d319b2419b409a8, 0xff3d81e5df1aa419, 0xbc3e483afcb82947, 0xd40d49174aab1cc5, 0x3fb05b7a28266895, 0x0c84ee012b39bf21, 0xd9d832d5998a52e6, 0xb0341b6491614ef5, 0x8ec69b03e86e5bbe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
	  {0xecec196accc52972, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff} },
	{ 384, 'n', 6,
	  {0x61c2df96fa5e2d63, 0x95522f9a67574c02, 0xef2eab42fd8cfe33, 0xe57b37e7704b3d09, 0x182a3add9b872a76, 0xa40f9ca3df62692c, 0xe2db0c01afd798c2, 0x942af46d1c8d5358, 0xa32dc48296ce3859, 0x5d3ffd11a23c1698, 0xdd66a3582e62fe86, 0xbf3ba33a183c74e2},
	  {0xdb7ffd331cb763d0, 0x56f9d21d30b955ef, 0x831ef3b99fa6b5e9, 0x5a4efd072cb961dc, 0x0021e79203621789, 0x5dc1b994c2e8530c} },
	/* r1 < r2 in HAC 14.42 step 3: the subtraction borrows */
	{ 256, 'p', 4,
	  {0xfffffffeffffffff, 0xfffffffffffffffe, 0x0000000100000000, 0x0000000100000000, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000},
	  {0xfffffffffffffffe, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001} },
	{ 256, 'n', 4,
	  {0xfc632550ffffffff, 0x9ad16947f01cf013, 0xbce6faad63fe9932, 0x00000000ffffffff, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000},
	  {0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000} },
	{ 384, 'p', 6,
	  {0x00000000fffffffe, 0xffffffffffffffff, 0xfffffffefffffffe, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0x00000000fffffffe, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff} },
	{ 384, 'n', 6,
	  {0xecec196accc52972, 0x4506271d1575d0ed, 0x1f7d5b343ce7d55a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000000, 0x0000000000000001, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000},
	  {0xecec196accc52972, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff} },
};

static ccec_const_cp_t curve(unsigned bits) {
	return bits == 256 ? ccec_cp_256() : ccec_cp_384();
}

int main(void) {
	int failures = 0;

	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		ccec_const_cp_t cp = curve(vectors[i].curve);
		cc_size n = vectors[i].n;
		cc_unit r[6];
		memset(r, 0, sizeof r);

		if (vectors[i].modulus == 'p') {
			cczp_mod(cp.zp, r, (const cc_unit*)vectors[i].x, NULL);
		} else {
			/* the order with its reciprocal, built as ccec_verify does */
			uint8_t zp_bytes[cczp_size(ccn_sizeof_n(n))];
			memset(zp_bytes, 0, sizeof zp_bytes);
			cczp_t zp = (cczp_t)(struct cczp*)zp_bytes;
			CCZP_N(zp) = n;
			memcpy(CCZP_PRIME(zp), ccec_cp_o(cp), ccn_sizeof_n((2 * n) + 1));
			zp.zp->mod_prime = cczp_mod;
			cczp_mod(zp, r, (const cc_unit*)vectors[i].x, NULL);
		}

		if (memcmp(r, vectors[i].expected, ccn_sizeof_n(n)) != 0) {
			printf("FAIL P-%u mod %c, vector %zu\n", vectors[i].curve, vectors[i].modulus, i);
			failures++;
		}
	}

	printf("%d failure(s) in %zu vectors\n", failures, sizeof(vectors) / sizeof(vectors[0]));
	return failures != 0;
}
