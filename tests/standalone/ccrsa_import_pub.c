/*
 * ccrsa_import_pub must report an error, not success, for a malformed PKCS#1
 * RSAPublicKey, and must still import a well-formed one. Each input is copied to
 * its own exact-size heap block so AddressSanitizer reports any over-read.
 *
 * Build and run from the repository root (on an aarch64 host add -D__arm64__ so
 * cc_unit is 64-bit):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ccrsa_import_pub.c \
 *     -o /tmp/ccrsa_import_pub && /tmp/ccrsa_import_pub
 */
#include <corecrypto/ccrsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct {
	const char* what;
	unsigned len;
	unsigned char der[32];
	int want_ok;
} inputs[] = {
	// 128-bit odd modulus (two cc_unit on 64-bit), e = 65537. (A one-unit modulus
	// reaches ccn_div_long's d[n - 2] and is a separate, existing problem.)
	{ "128-bit modulus, e = 65537", 25,
	  {0x30, 0x17, 0x02, 0x10, 0x41, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	   0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x11, 0x02, 0x03, 0x01, 0x00, 0x01}, 1 },
	{ "empty input", 0, {0}, 0 },
	{ "30 00", 2, {0x30, 0x00}, 0 },
	{ "wrong outer tag", 9, {0x31, 0x07, 0x02, 0x02, 0x01, 0x23, 0x02, 0x01, 0x03}, 0 },
	{ "SEQUENCE length past the end", 9, {0x30, 0x08, 0x02, 0x02, 0x01, 0x23, 0x02, 0x01, 0x03}, 0 },
	{ "modulus is not an INTEGER", 9, {0x30, 0x07, 0x04, 0x02, 0x01, 0x23, 0x02, 0x01, 0x03}, 0 },
	{ "modulus INTEGER with no content", 6, {0x30, 0x04, 0x02, 0x00, 0x02, 0x00}, 0 },
	{ "exponent missing", 6, {0x30, 0x04, 0x02, 0x02, 0x01, 0x23}, 0 },
	{ "exponent INTEGER runs past the SEQUENCE", 9, {0x30, 0x05, 0x02, 0x02, 0x01, 0x23, 0x02, 0x01, 0x03}, 0 },
	// 1-byte modulus (one cc_unit), 9-byte exponent: the exponent does not fit
	{ "exponent wider than the modulus allocation", 16,
	  {0x30, 0x0e, 0x02, 0x01, 0x05, 0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}, 0 },
};

/*
 * The caller allocates the context for `cap` units and stores that in ccrsa_ctx_n(key).
 * The import must fail, and must not write outside the block, when the modulus needs more
 * units; and must not count the leading zero octet of a DER INTEGER against the capacity.
 * The context is an exact-size heap block so AddressSanitizer sees any write past its end.
 */
static int import_with_capacity(const char* what, unsigned cap, unsigned mod_len, int pad, int want_ok) {
	uint8_t der[2 + 2 + 1 + 80 + 5];
	unsigned n = 0;
	unsigned body = (2 + (mod_len + pad)) + 5;
	der[n++] = 0x30;
	der[n++] = (uint8_t)body;
	der[n++] = 0x02;
	der[n++] = (uint8_t)(mod_len + pad);
	if (pad)
		der[n++] = 0;
	der[n++] = 0xc1; /* top bit set, odd last octet */
	memset(der + n, 0x5a, mod_len - 1);
	der[n + mod_len - 2] = 0xc3;
	n += mod_len - 1;
	static const uint8_t e[] = {0x02, 0x03, 0x01, 0x00, 0x01};
	memcpy(der + n, e, sizeof e);
	n += sizeof e;

	ccrsa_pub_ctx* key = (ccrsa_pub_ctx*)calloc(1, ccrsa_pub_ctx_size(ccn_sizeof_n(cap)));
	ccrsa_ctx_n(key) = cap;
	int rc = ccrsa_import_pub(key, n, der);
	free(key);
	if ((rc == 0) != want_ok) {
		printf("FAIL %s: rc=%d (want %s)\n", what, rc, want_ok ? "0" : "an error");
		return 1;
	}
	return 0;
}

static int check_capacity(void) {
	int f = 0;
	f += import_with_capacity("33-byte modulus, capacity 2 units", 2, 33, 0, 0);
	f += import_with_capacity("17-byte modulus, capacity 2 units", 2, 17, 0, 0);
	f += import_with_capacity("16-byte modulus with 00 pad, capacity 2 units", 2, 16, 1, 1);
	f += import_with_capacity("16-byte modulus, capacity 2 units", 2, 16, 0, 1);
	f += import_with_capacity("16-byte modulus, capacity 1 unit", 1, 16, 0, 0);
	f += import_with_capacity("64-byte modulus, capacity 8 units", 8, 64, 1, 1);
	return f;
}

int main(void) {
	int failures = 0;
	for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
		unsigned len = inputs[i].len;
		uint8_t* der = malloc(len);
		memcpy(der, inputs[i].der, len);
		ccrsa_full_ctx_decl(64, key);
		ccrsa_ctx_n(ccrsa_ctx_public(key)) = ccn_nof_size(64);
		int rc = ccrsa_import_pub(ccrsa_ctx_public(key), len, der);
		free(der);
		if ((rc == 0) != inputs[i].want_ok) {
			printf("FAIL %s: rc=%d (want %s)\n", inputs[i].what, rc, inputs[i].want_ok ? "0" : "an error");
			failures++;
		}
	}
	failures += check_capacity();
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
