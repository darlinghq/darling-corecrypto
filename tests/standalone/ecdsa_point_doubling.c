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
 * A valid P-256 signature whose verification adds a point to itself:
 * u1 * G == u2 * Q, so R = u1 * G + u2 * Q = 2 * (u1 * G) and the group law
 * (SEC 1 2.2.1) needs the doubling formula for that sum.
 *
 * Constructed with Python integers for the RFC 6979 A.2.5 key
 * (Q = d * G): take R = 2G, r = x(R) mod n, e = r * d mod n and s = e. Then
 * u1 = e / s = 1 and u2 = r / s = 1 / d, so u1 * G = u2 * Q = G. The
 * signature (r, s) on the digest e must verify, and must not verify for
 * the digest e + 1.
 *
 * Build and run from the repository root (on an aarch64 Linux host add
 * -D__arm64__ so cc_unit is 64-bit; add -m32 for 32-bit units):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ecdsa_point_doubling.c \
 *     -o /tmp/ecdsa_point_doubling && /tmp/ecdsa_point_doubling
 */
#include <corecrypto/ccec.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* RFC 6979 A.2.5 P-256 public key */
static const uint8_t pub[] = {0x04,
	0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d, 0x68,
	0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2, 0x9f, 0xb6,
	0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc, 0x64,
	0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46, 0x22, 0x99};

/* e = r * d mod n */
static const uint8_t digest[] = {
	0x3b, 0x5e, 0x64, 0xb9, 0xa8, 0x33, 0xe8, 0x78, 0xc8, 0x4b, 0x9d, 0x74, 0x7a, 0xe1, 0x6e, 0x6b,
	0x25, 0x5d, 0x90, 0x32, 0x35, 0xeb, 0xed, 0xc0, 0x81, 0xe2, 0xc7, 0xb6, 0xea, 0x41, 0x5e, 0x6e};

/* SEQUENCE { INTEGER r = x(2G) mod n, INTEGER s = e } */
static const uint8_t sig[] = {0x30, 0x44,
	0x02, 0x20,
	0x7c, 0xf2, 0x7b, 0x18, 0x8d, 0x03, 0x4f, 0x7e, 0x8a, 0x52, 0x38, 0x03, 0x04, 0xb5, 0x1a, 0xc3,
	0xc0, 0x89, 0x69, 0xe2, 0x77, 0xf2, 0x1b, 0x35, 0xa6, 0x0b, 0x48, 0xfc, 0x47, 0x66, 0x99, 0x78,
	0x02, 0x20,
	0x3b, 0x5e, 0x64, 0xb9, 0xa8, 0x33, 0xe8, 0x78, 0xc8, 0x4b, 0x9d, 0x74, 0x7a, 0xe1, 0x6e, 0x6b,
	0x25, 0x5d, 0x90, 0x32, 0x35, 0xeb, 0xed, 0xc0, 0x81, 0xe2, 0xc7, 0xb6, 0xea, 0x41, 0x5e, 0x6e};

int main(void) {
	int failures = 0;
	alarm(120);

	ccec_const_cp_t cp = ccec_cp_256();
	ccec_pub_ctx_decl_cp(cp, key);
	if (ccec_import_pub(cp, sizeof pub, pub, key) != 0) {
		printf("FAIL public key import\n");
		return 1;
	}

	bool valid = false;
	if (ccec_verify(key, sizeof digest, digest, sizeof sig, sig, &valid) != 0 || !valid) {
		printf("FAIL signature with u1 * G == u2 * Q does not verify\n");
		failures++;
	}

	uint8_t other[sizeof digest];
	memcpy(other, digest, sizeof other);
	other[sizeof other - 1] ^= 1;
	valid = true;
	if (ccec_verify(key, sizeof other, other, sizeof sig, sig, &valid) != 0 || valid) {
		printf("FAIL the same signature verifies for another digest\n");
		failures++;
	}

	printf("%d failure(s)\n", failures);
	fflush(stdout);
	return failures != 0;
}
