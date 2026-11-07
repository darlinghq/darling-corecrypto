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
 * ccec_import_pub + ccec_verify against the public ECDSA verification
 * vectors in tests/vectors (NIST CAVP FIPS 186-4 SigVer, Wycheproof
 * EcdsaVerify; sources and licenses in tests/vectors/SOURCES).
 * scripts/ecdsa-vectors.py turns them into one line per test on stdin:
 *
 *   <id> <curve bits> <V|I|A> <X9.63 public key> <digest> <DER signature>
 *
 * V must verify, I must not (a key the import refuses counts as not
 * verifying), A may go either way. Each signature sits in an exact-size heap
 * block so AddressSanitizer reports reads past its end.
 *
 * Build and run from the repository root (on an aarch64 Linux host add
 * -D__arm64__ so cc_unit is 64-bit; add -m32 for 32-bit units):
 *   clang -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ecdsa_vectors.c \
 *     -o /tmp/ecdsa_vectors
 *   python3 scripts/ecdsa-vectors.py tests/vectors/cavp/*.rsp \
 *     tests/vectors/wycheproof/*.json | /tmp/ecdsa_vectors
 */
#include <corecrypto/ccec.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FIELD 16384

static const struct {
	unsigned bits;
	ccec_const_cp_t (*cp)(void);
} curves[] = {
	{ 192, ccec_cp_192 },
	{ 224, ccec_cp_224 },
	{ 256, ccec_cp_256 },
	{ 384, ccec_cp_384 },
	{ 521, ccec_cp_521 },
};

static struct {
	unsigned run, failed;
} stats[sizeof(curves) / sizeof(curves[0])];

static int hexval(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* "-" is the empty string; returns -1 on malformed hex */
static long from_hex(const char* hex, uint8_t* out, size_t max) {
	if (strcmp(hex, "-") == 0)
		return 0;
	size_t len = strlen(hex);
	if (len % 2 != 0 || len / 2 > max)
		return -1;
	for (size_t i = 0; i < len / 2; i++) {
		int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return -1;
		out[i] = (uint8_t)(hi << 4 | lo);
	}
	return (long)(len / 2);
}

int main(void) {
	static char line[4 * MAX_FIELD];
	static char id[256], expected[4], pub_hex[MAX_FIELD], digest_hex[MAX_FIELD], sig_hex[MAX_FIELD];
	static uint8_t pub[MAX_FIELD / 2], digest[MAX_FIELD / 2], sig_buf[MAX_FIELD / 2];
	unsigned bits;
	unsigned total = 0, failures = 0, malformed = 0;

	alarm(1800);

	while (fgets(line, sizeof line, stdin)) {
		if (sscanf(line, "%255s %u %3s %16383s %16383s %16383s", id, &bits, expected, pub_hex, digest_hex, sig_hex) != 6) {
			printf("MALFORMED line: %s", line);
			malformed++;
			continue;
		}

		size_t c = 0;
		while (c < sizeof(curves) / sizeof(curves[0]) && curves[c].bits != bits)
			c++;
		long pub_len = from_hex(pub_hex, pub, sizeof pub);
		long digest_len = from_hex(digest_hex, digest, sizeof digest);
		long sig_len = from_hex(sig_hex, sig_buf, sizeof sig_buf);
		if (c == sizeof(curves) / sizeof(curves[0]) || pub_len < 0 || digest_len < 0 || sig_len < 0) {
			printf("MALFORMED %s\n", id);
			malformed++;
			continue;
		}

		ccec_const_cp_t cp = curves[c].cp();
		ccec_pub_ctx_decl_cp(cp, key);
		bool valid = false;
		bool imported = ccec_import_pub(cp, (size_t)pub_len, pub, key) == 0;
		int rc = 0;
		if (imported) {
			uint8_t* sig = malloc(sig_len ? (size_t)sig_len : 1);
			memcpy(sig, sig_buf, (size_t)sig_len);
			rc = ccec_verify(key, (size_t)digest_len, digest, (size_t)sig_len, sig, &valid);
			free(sig);
		}

		bool ok;
		if (expected[0] == 'V')
			ok = imported && rc == 0 && valid;
		else if (expected[0] == 'I')
			ok = !valid;
		else
			ok = true;

		total++;
		stats[c].run++;
		if (!ok) {
			stats[c].failed++;
			failures++;
			printf("FAIL %s P-%u: expected %s, got %s\n", id, bits,
			       expected[0] == 'V' ? "valid" : "invalid",
			       !imported ? "key import failure" : rc != 0 ? "an error" : valid ? "valid" : "invalid");
		}
		fflush(stdout);
	}

	for (size_t c = 0; c < sizeof(curves) / sizeof(curves[0]); c++)
		if (stats[c].run)
			printf("P-%u: %u of %u failed\n", curves[c].bits, stats[c].failed, stats[c].run);
	printf("%u failure(s) in %u vectors%s\n", failures, total, malformed ? ", malformed input" : "");
	return failures != 0 || malformed != 0 || total == 0;
}
