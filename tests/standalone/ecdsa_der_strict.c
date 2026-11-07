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
 * ccec_verify takes the signature as a DER Ecdsa-Sig-Value (ANSI X9.62,
 * SEC 1 C.5). Starting from the RFC 6979 A.2.5 P-256/SHA-256 "sample"
 * signature, re-encode r and s and check that:
 *
 * - the DER encoding verifies, and so does (r, n - s): FIPS 186-4 6.4 has
 *   no low-s rule, so both halves of the malleable pair are valid;
 * - BER-only forms are rejected (ITU-T X.690 10.1 and 8.3.2): long-form
 *   lengths below 128, a redundant leading zero octet, and an INTEGER whose
 *   top bit is set without the zero octet (a negative number);
 * - r + n (out of range, and wider than the order) is rejected.
 *
 * Build and run from the repository root (on an aarch64 Linux host add
 * -D__arm64__ so cc_unit is 64-bit; add -m32 for 32-bit units):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ecdsa_der_strict.c \
 *     -o /tmp/ecdsa_der_strict && /tmp/ecdsa_der_strict
 */
#include <corecrypto/ccec.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* RFC 6979 A.2.5: P-256 public key, SHA-256("sample"), and the signature */
static const uint8_t pub[] = {0x04,
	0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
	0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
	0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
	0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};
static const uint8_t digest[] = {
	0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad, 0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7,
	0x1a, 0x83, 0x1d, 0x02, 0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad, 0xd1, 0xbf};
static const uint8_t r[] = {
	0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
	0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8, 0x4e, 0xaf, 0x37, 0x16};
static const uint8_t s[] = {
	0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2, 0x9f, 0x65,
	0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f, 0x84, 0x3a, 0xcd, 0xa8};
/* n - s, computed with Python integers */
static const uint8_t s_low[] = {
	0x08, 0x34, 0xe3, 0x6a, 0xd2, 0x9a, 0x83, 0xbf, 0x2b, 0xc9, 0x38, 0x5e, 0x49, 0x1d, 0x60, 0x99,
	0xc8, 0xfd, 0xf9, 0xd1, 0xed, 0x67, 0xaa, 0x7e, 0xa5, 0xf5, 0x1f, 0x93, 0x78, 0x28, 0x57, 0xa9};
/* r + n, computed with Python integers (257 bits) */
static const uint8_t r_plus_n[] = {0x01,
	0xef, 0xd4, 0x8b, 0x29, 0xac, 0xb6, 0xa8, 0xfe, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e, 0x81, 0xd6,
	0x5a, 0x13, 0x82, 0x28, 0xfd, 0xc2, 0x98, 0x16, 0xb7, 0x06, 0xd9, 0x6b, 0x4b, 0x12, 0x5c, 0x67};

enum {
	LONG_SEQ_LEN = 1, /* SEQUENCE length as 81 xx */
	LONG_R_LEN = 2,   /* r length as 81 xx */
	R_EXTRA_ZERO = 4, /* one more 00 octet in front of r */
	R_NO_PAD = 8,     /* r without the 00 octet its top bit needs */
	S_EXTRA_ZERO = 16,
};

static size_t integer(uint8_t* out, const uint8_t* v, size_t len, int long_len, int extra_zero, int no_pad) {
	size_t pad = (v[0] & 0x80) && !no_pad ? 1 : 0;
	size_t content = len + pad + (extra_zero ? 1 : 0);
	size_t o = 0;
	out[o++] = 0x02;
	if (long_len)
		out[o++] = 0x81;
	out[o++] = (uint8_t)content;
	if (extra_zero)
		out[o++] = 0;
	if (pad)
		out[o++] = 0;
	memcpy(out + o, v, len);
	return o + len;
}

static size_t encode(uint8_t* out, const uint8_t* rv, size_t r_len, const uint8_t* sv, size_t s_len, int flags) {
	uint8_t body[2 * 40];
	size_t b = integer(body, rv, r_len, flags & LONG_R_LEN, flags & R_EXTRA_ZERO, flags & R_NO_PAD);
	b += integer(body + b, sv, s_len, 0, flags & S_EXTRA_ZERO, 0);
	size_t o = 0;
	out[o++] = 0x30;
	if (flags & LONG_SEQ_LEN)
		out[o++] = 0x81;
	out[o++] = (uint8_t)b;
	memcpy(out + o, body, b);
	return o + b;
}

static int failures;

static void check(const char* what, const uint8_t* rv, size_t r_len, const uint8_t* sv, size_t s_len, int flags, bool want) {
	uint8_t tmp[100];
	size_t len = encode(tmp, rv, r_len, sv, s_len, flags);
	/* exact-size heap copy so ASan reports any read past the signature */
	uint8_t* sig = malloc(len);
	memcpy(sig, tmp, len);

	ccec_const_cp_t cp = ccec_cp_256();
	ccec_pub_ctx_decl_cp(cp, key);
	bool valid = !want;
	if (ccec_import_pub(cp, sizeof pub, pub, key) != 0) {
		printf("FAIL %s: public key import\n", what);
		failures++;
	} else if (ccec_verify(key, sizeof digest, digest, len, sig, &valid) != 0 || valid != want) {
		printf("FAIL %s: %s\n", what, want ? "rejected" : "accepted");
		failures++;
	}
	free(sig);
}

int main(void) {
	alarm(120);

	check("DER signature", r, sizeof r, s, sizeof s, 0, true);
	check("(r, n - s)", r, sizeof r, s_low, sizeof s_low, 0, true);

	check("long-form SEQUENCE length", r, sizeof r, s, sizeof s, LONG_SEQ_LEN, false);
	check("long-form INTEGER length", r, sizeof r, s, sizeof s, LONG_R_LEN, false);
	check("redundant leading zero in r", r, sizeof r, s, sizeof s, R_EXTRA_ZERO, false);
	check("redundant leading zero in s", r, sizeof r, s, sizeof s, S_EXTRA_ZERO, false);
	check("redundant leading zero in a low s", r, sizeof r, s_low, sizeof s_low, S_EXTRA_ZERO, false);
	check("r with its top bit set and no zero octet", r, sizeof r, s, sizeof s, R_NO_PAD, false);
	check("r + n", r_plus_n, sizeof r_plus_n, s, sizeof s, 0, false);

	printf("%d failure(s)\n", failures);
	return failures != 0;
}
