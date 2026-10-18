/*
 * Malformed DER must make every decoder return NULL without reading past
 * der_end; well-formed DER must still decode. Each input is copied to its own
 * heap block so AddressSanitizer reports any over-read.
 *
 * Build and run from the repository root on an x86_64 host (on an aarch64
 * Linux host add -D__arm64__ so cc_unit is 64-bit):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ccder_malformed.c \
 *     -o /tmp/ccder_malformed && /tmp/ccder_malformed
 */
#include <corecrypto/ccder.h>
#include <corecrypto/ccn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum decoder { SEQUENCE, UINT, OID, SEQII };

static const struct {
	const char* what;
	unsigned len;
	unsigned char der[16];
	enum decoder decoder;
} malformed[] = {
	{ "empty input", 0, {0}, SEQUENCE },
	{ "tag without length", 1, {0x30}, SEQUENCE },
	{ "length past the end", 2, {0x30, 0x05}, SEQUENCE },
	{ "long length past size_t", 6, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, SEQUENCE },
	{ "long form with no length bytes", 2, {0x30, 0x80}, SEQUENCE },
	{ "high tag number truncated", 2, {0x1f, 0x81}, SEQUENCE },
	// Ten continuation bytes, so the last shift would be by 70 on a 64-bit ccder_tag.
	{ "high tag number wider than ccder_tag", 13,
	  {0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, SEQUENCE },
	{ "SET where SEQUENCE expected", 2, {0x31, 0x00}, SEQUENCE },
	{ "INTEGER body truncated", 3, {0x02, 0x04, 0x00}, UINT },
	{ "INTEGER with no content octets", 2, {0x02, 0x00}, UINT },
	{ "OCTET STRING where INTEGER expected", 3, {0x04, 0x01, 0x05}, UINT },
	{ "OID body truncated", 2, {0x06, 0x09}, OID },
	// An empty SEQUENCE followed by two INTEGERs: the components live outside the
	// structure, so the sequence decoder must not reach them.
	{ "INTEGERs outside an empty SEQUENCE", 8,
	  {0x30, 0x00, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07}, SEQII },
};

static const uint8_t* decode(enum decoder decoder, const uint8_t* der, const uint8_t* der_end) {
	switch (decoder) {
		case SEQUENCE: {
			const uint8_t* body_end = NULL;
			return ccder_decode_sequence_tl(&body_end, der, der_end);
		}
		case UINT: {
			cc_unit r[4];
			return ccder_decode_uint(4, r, der, der_end);
		}
		case OID: {
			ccoid_t oid;
			return ccder_decode_oid(&oid, der, der_end);
		}
		case SEQII: {
			cc_unit r[1] = {0}, s[1] = {0};
			return ccder_decode_seqii(1, r, s, der, der_end);
		}
	}
	return NULL;
}

int main(void) {
	int failures = 0;

	for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
		unsigned len = malformed[i].len;
		uint8_t* der = malloc(len ? len : 1);
		memcpy(der, malformed[i].der, len);
		if (decode(malformed[i].decoder, der, der + len) != NULL) {
			printf("FAIL %s: decoder did not return NULL\n", malformed[i].what);
			failures++;
		}
		free(der);
	}

	/* SEQUENCE { INTEGER 5, INTEGER 7 } */
	static const uint8_t good[] = {0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07};
	uint8_t* der = malloc(sizeof good);
	memcpy(der, good, sizeof good);
	const uint8_t* der_end = der + sizeof good;
	const uint8_t* body_end = NULL;
	cc_unit r[1] = {0}, s[1] = {0};
	const uint8_t* p = ccder_decode_sequence_tl(&body_end, der, der_end);
	p = ccder_decode_uint(1, r, p, body_end);
	p = ccder_decode_uint(1, s, p, body_end);
	if (p != der_end || body_end != der_end || r[0] != 5 || s[0] != 7) {
		printf("FAIL well-formed SEQUENCE of two INTEGERs did not decode\n");
		failures++;
	}
	free(der);

	printf("%d failure(s)\n", failures);
	return failures != 0;
}
