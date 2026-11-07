/*
 * Copyright (c) 2026 Darling Developers
 *
 * This file is part of Darling CoreCrypto.
 *
 * Darling is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * ccn_mul(n, r, s, t) must store the full 2n-unit product s * t (ccn.h).
 *
 * - Fixed vectors: products computed with Python integers, given as
 *   big-endian hex so they hold for 32- and 64-bit units alike.
 * - Carry chains: (b^n - 1)^2 = b^2n - 2 b^n + 1 and (b^n - 1) * 1, for
 *   n = 1 ... 18, checked against that closed form.
 * - Random operands, n = 1 ... 18: compared with a bit-serial
 *   shift-and-add reference written here, which shares no code with ccn_mul.
 *
 * Build and run from the repository root (on an aarch64 Linux host add
 * -D__arm64__ so cc_unit is 64-bit; add -m32 for 32-bit units):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ccn_mul.c \
 *     -o /tmp/ccn_mul && /tmp/ccn_mul
 */
#include <corecrypto/ccn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_N 18

static int failures;

static const struct {
	const char* what;
	const char* s;
	const char* t;
	const char* product;
} vectors[] = {
	/* Python: hex(a * b) */
	{ "64-bit operands",
	  "fedcba9876543210", "0123456789abcdef",
	  "0121fa00ad77d7422236d88fe5618cf0" },
	{ "128-bit, carry out of every unit",
	  "ffffffffffffffffffffffffffffffff", "fffffffffffffffffffffffffffffffe",
	  "fffffffffffffffffffffffffffffffd00000000000000000000000000000002" },
	{ "256-bit (P-256 prime squared)",
	  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	  "fffffffe00000002fffffffe0000000100000001fffffffe00000001fffffffe00000001fffffffefffffffffffffffffffffffe000000000000000000000001" },
	{ "192-bit times 64-bit value in 192 bits",
	  "123456789abcdef0fedcba9876543210ffffffffffffffff",
	  "000000000000000000000000000000008000000000000001",
	  "00000000000000000000000000000000091a2b3c4d5e6f7891a2b3c4d5e6f7f97edcba98765432107fffffffffffffff" },
};

static int hexval(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

static size_t from_hex(const char* hex, uint8_t* out) {
	size_t len = strlen(hex) / 2;
	for (size_t i = 0; i < len; i++)
		out[i] = (uint8_t)(hexval(hex[2 * i]) << 4 | hexval(hex[2 * i + 1]));
	return len;
}

/* Reference: r = s * t, one bit of t at a time; r has 2n units. */
static void reference_mul(cc_size n, cc_unit* r, const cc_unit* s, const cc_unit* t) {
	cc_unit shifted[2 * MAX_N];
	memset(r, 0, ccn_sizeof_n(2 * n));
	memset(shifted, 0, sizeof shifted);
	memcpy(shifted, s, ccn_sizeof_n(n));

	for (size_t bit = 0; bit < n * CCN_UNIT_BITS; bit++) {
		if ((t[bit / CCN_UNIT_BITS] >> (bit % CCN_UNIT_BITS)) & 1) {
			cc_unit carry = 0;
			for (cc_size i = 0; i < 2 * n; i++) {
				cc_unit sum = r[i] + shifted[i];
				cc_unit c1 = sum < r[i];
				r[i] = sum + carry;
				carry = c1 | (r[i] < sum);
			}
		}
		/* shifted <<= 1 */
		cc_unit top = 0;
		for (cc_size i = 0; i < 2 * n; i++) {
			cc_unit next = shifted[i] >> (CCN_UNIT_BITS - 1);
			shifted[i] = (shifted[i] << 1) | top;
			top = next;
		}
	}
}

/* Heap blocks of exactly the size ccn_mul may touch, so ASan sees overruns. */
static void check_product(const char* what, cc_size n, const cc_unit* s, const cc_unit* t, const cc_unit* want) {
	cc_unit* hs = malloc(ccn_sizeof_n(n));
	cc_unit* ht = malloc(ccn_sizeof_n(n));
	cc_unit* hr = malloc(ccn_sizeof_n(2 * n));
	memcpy(hs, s, ccn_sizeof_n(n));
	memcpy(ht, t, ccn_sizeof_n(n));
	memset(hr, 0xa5, ccn_sizeof_n(2 * n));

	ccn_mul(n, hr, hs, ht);

	if (memcmp(hr, want, ccn_sizeof_n(2 * n)) != 0) {
		printf("FAIL %s (n = %u)\n", what, (unsigned)n);
		failures++;
	}
	if (memcmp(hs, s, ccn_sizeof_n(n)) != 0 || memcmp(ht, t, ccn_sizeof_n(n)) != 0) {
		printf("FAIL %s (n = %u): operands modified\n", what, (unsigned)n);
		failures++;
	}
	free(hs);
	free(ht);
	free(hr);
}

static void check_vectors(void) {
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		uint8_t buf[2 * MAX_N * sizeof(cc_unit)];
		cc_unit s[MAX_N], t[MAX_N], want[2 * MAX_N];

		size_t len = from_hex(vectors[i].s, buf);
		cc_size n = ccn_nof_size(len);
		ccn_read_uint(n, s, len, buf);
		len = from_hex(vectors[i].t, buf);
		ccn_read_uint(n, t, len, buf);
		len = from_hex(vectors[i].product, buf);
		ccn_read_uint(2 * n, want, len, buf);

		check_product(vectors[i].what, n, s, t, want);
	}
}

static void check_carry_chains(void) {
	for (cc_size n = 1; n <= MAX_N; n++) {
		cc_unit ones[MAX_N], one[MAX_N], want[2 * MAX_N];
		memset(ones, 0xff, sizeof ones);
		memset(one, 0, sizeof one);
		one[0] = 1;

		/* (b^n - 1)^2 = b^2n - 2 b^n + 1: units 1 ... n-1 are 0, unit n is
		 * b - 2, units n+1 ... 2n-1 are b - 1, unit 0 is 1. */
		memset(want, 0, sizeof want);
		want[0] = 1;
		want[n] = CCN_UNIT_MASK - 1;
		for (cc_size i = n + 1; i < 2 * n; i++)
			want[i] = CCN_UNIT_MASK;
		check_product("all-ones squared", n, ones, ones, want);

		/* (b^n - 1) * 1 */
		memset(want, 0, sizeof want);
		memset(want, 0xff, ccn_sizeof_n(n));
		check_product("all-ones times one", n, ones, one, want);
		check_product("one times all-ones", n, one, ones, want);

		/* 0 * (b^n - 1) */
		memset(want, 0, sizeof want);
		memset(one, 0, sizeof one);
		check_product("zero times all-ones", n, one, ones, want);
	}
}

static uint64_t prng_state = 0x0123456789abcdefULL;

static cc_unit prng(void) {
	/* xorshift64; only needs to be deterministic */
	prng_state ^= prng_state << 13;
	prng_state ^= prng_state >> 7;
	prng_state ^= prng_state << 17;
	return (cc_unit)prng_state;
}

static void check_random(void) {
	for (cc_size n = 1; n <= MAX_N; n++) {
		for (int round = 0; round < 50; round++) {
			cc_unit s[MAX_N], t[MAX_N], want[2 * MAX_N];
			for (cc_size i = 0; i < n; i++) {
				s[i] = prng();
				t[i] = prng();
			}
			/* also exercise operands whose top units are zero */
			if (round % 5 == 1)
				s[n - 1] = 0;
			if (round % 5 == 2)
				for (cc_size i = n / 2; i < n; i++)
					t[i] = 0;
			if (round % 5 == 3)
				for (cc_size i = 0; i < n; i++)
					s[i] |= (cc_unit)1 << (CCN_UNIT_BITS - 1);

			reference_mul(n, want, s, t);
			check_product("random operands", n, s, t, want);
		}
	}
}

int main(void) {
	check_vectors();
	check_carry_chains();
	check_random();
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
