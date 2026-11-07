/*
 * ccn_make_recip(n, recip, d) must store floor((2^64)^(2n) / d) in n + 1 units (also for moduli whose top unit has
 * leading zero bits, such as the P-224 and P-521 primes, where the dividend must be
 * normalized together with the divisor)
 * and must not write outside its scratch buffers (the quotient loop used to
 * store a digit one unit past an n + 1 unit buffer, which AddressSanitizer
 * reports as a dynamic-stack-buffer-overflow). Expected values computed with
 * Python big integers: 2**(64*2n) // d.
 *
 * Build and run from the repository root (on an aarch64 host add -D__arm64__ so
 * cc_unit is 64-bit; this test needs 64-bit units):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ccn_make_recip.c \
 *     -o /tmp/ccn_make_recip && /tmp/ccn_make_recip
 */
#include <corecrypto/ccn.h>
#include <stdio.h>
#include <string.h>

static int failures;

static void check(const char* what, cc_size n, const cc_unit* d, const cc_unit* want) {
	cc_unit got[16];
	memset(got, 0xaa, sizeof got);
	ccn_make_recip(n, got, d);
	if (memcmp(got, want, ccn_sizeof_n(n + 1)) != 0) {
		printf("FAIL %s\n", what);
		failures++;
	}
}

int main(void) {

#if CCN_UNIT_SIZE == 8
	/* d = 0x41234567_89abcdef_fedcba98_76543211, quotient 0x3_ee1d10c4c0478bbe_17c115bf745851ac */
	const cc_unit d2[2] = {0xfedcba9876543211ULL, 0x0123456789abcdefULL | 0x4000000000000000ULL};
	const cc_unit want2[3] = {0x17c115bf745851acULL, 0xee1d10c4c0478bbeULL, 0x3};
	cc_unit got2[3];
	memset(got2, 0xaa, sizeof got2);
	ccn_make_recip(2, got2, d2);
	if (memcmp(got2, want2, sizeof want2) != 0) {
		printf("FAIL 2-unit modulus\n");
		failures++;
	}

	/* d = 0xc123456789abcdef_0123456789abcdef_fedcba9876543211, quotient
	 * 0x1_535291881b255354_7147df7aaedcecf4_b18deeec193d99b6 */
	const cc_unit d3[3] = {0xfedcba9876543211ULL, 0x0123456789abcdefULL, 0xc123456789abcdefULL};
	const cc_unit want3[4] = {0xb18deeec193d99b6ULL, 0x7147df7aaedcecf4ULL, 0x535291881b255354ULL, 0x1};
	cc_unit got3[4];
	memset(got3, 0xaa, sizeof got3);
	ccn_make_recip(3, got3, d3);
	if (memcmp(got3, want3, sizeof want3) != 0) {
		printf("FAIL 3-unit modulus\n");
		failures++;
	}

	/* p224 prime */
	const cc_unit d_p224[4] = {0x0000000000000001ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL, 0x00000000ffffffffULL};
	const cc_unit want_p224[5] = {0x00000000ffffffffULL, 0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL, 0x0000000100000000ULL};
	check("p224", 4, d_p224, want_p224);

	/* p521 prime */
	const cc_unit d_p521[9] = {0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x00000000000001ffULL};
	const cc_unit want_p521[10] = {0x0000000000000000ULL, 0x0000400000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL, 0x0080000000000000ULL};
	check("p521", 9, d_p521, want_p521);

#else
	printf("skipped: needs 64-bit cc_unit\n");
#endif

	printf("%d failure(s)\n", failures);
	return failures != 0;
}
