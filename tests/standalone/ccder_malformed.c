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

enum decoder { SEQUENCE, UINT, UINT64, OID, SEQII };

static const struct {
	const char* what;
	unsigned len;
	unsigned char der[40];
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
	// Eleven continuation octets: the last shift would be by 70 on a 64-bit ccder_tag.
	{ "high tag number with 11 continuation octets", 14,
	  {0x1f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01, 0x00}, SEQUENCE },
	{ "SET where SEQUENCE expected", 2, {0x31, 0x00}, SEQUENCE },
	{ "INTEGER body truncated", 3, {0x02, 0x04, 0x00}, UINT },
	{ "INTEGER with no content octets", 2, {0x02, 0x00}, UINT },
	{ "OCTET STRING where INTEGER expected", 3, {0x04, 0x01, 0x05}, UINT },
	// 33 significant bytes do not fit in cc_unit r[4] (32 bytes).
	{ "INTEGER wider than the destination", 35,
	  {0x02, 0x21, 0x01}, UINT },
	{ "9-byte INTEGER into uint64", 11,
	  {0x02, 0x09, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}, UINT64 },
	{ "uint64 INTEGER with no content octets", 2, {0x02, 0x00}, UINT64 },
	{ "uint64 INTEGER body truncated", 4, {0x02, 0x09, 0x01, 0x00}, UINT64 },
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
		case UINT64: {
			uint64_t r;
			return ccder_decode_uint64(&r, der, der_end);
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
		uint8_t* der = malloc(len); /* exact size: ASan sees any over-read, even of one byte */
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

	/* Edge cases that must decode, in exact-size heap blocks (the all-zero INTEGERs once
	 * read the byte after the end). */
	static const struct {
		const char* what;
		unsigned len;
		unsigned char der[16];
		enum decoder decoder;
		uint64_t want;
	} wellformed[] = {
		{ "INTEGER 0", 3, {0x02, 0x01, 0x00}, UINT, 0 },
		{ "INTEGER 00 00", 4, {0x02, 0x02, 0x00, 0x00}, UINT, 0 },
		{ "INTEGER 0 as uint64", 3, {0x02, 0x01, 0x00}, UINT64, 0 },
		{ "INTEGER 00 00 as uint64", 4, {0x02, 0x02, 0x00, 0x00}, UINT64, 0 },
		{ "8 significant bytes as uint64", 11, {0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, UINT64, ~(uint64_t)0 },
	};
	for (size_t i = 0; i < sizeof(wellformed) / sizeof(wellformed[0]); i++) {
		unsigned len = wellformed[i].len;
		uint8_t* d = malloc(len);
		memcpy(d, wellformed[i].der, len);
		uint64_t got = 0;
		const uint8_t* end;
		if (wellformed[i].decoder == UINT64) {
			end = ccder_decode_uint64(&got, d, d + len);
		} else {
			cc_unit r[4] = {1, 1, 1, 1};
			end = ccder_decode_uint(4, r, d, d + len);
			got = r[0] | r[1] | r[2] | r[3];
		}
		if (end != d + len || got != wellformed[i].want) {
			printf("FAIL %s: end %s, value %llu\n", wellformed[i].what, end == d + len ? "ok" : "wrong", (unsigned long long)got);
			failures++;
		}
		free(d);
	}

	printf("%d failure(s)\n", failures);
	return failures != 0;
}
