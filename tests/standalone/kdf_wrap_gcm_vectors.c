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
 * HMAC with long keys, HKDF, PBKDF2, AES key wrap and GCM against published
 * test vectors:
 * - HMAC: RFC 4231 test cases 6 and 7 (a key longer than the block, which
 *   RFC 2104 hashes first) with SHA-256 and SHA-512. HKDF and PBKDF2 depend on it.
 * - HKDF: RFC 5869 appendix A, test cases 1 to 4 (SHA-256 and SHA-1).
 * - PBKDF2: RFC 6070 (HMAC-SHA1) and RFC 7914 section 11 (HMAC-SHA256).
 * - AES key wrap: RFC 3394 section 4, all six cases, wrapping and unwrapping.
 * - GCM: test cases 2, 4, 5 and 6 of "The Galois/Counter Mode of Operation"
 *   (McGrew and Viega), so 96-bit, 64-bit and 480-bit IVs, through the
 *   one-shot functions and through ccgcm_set_iv_legacy.
 * An empty GCM IV has no published vector. Its expected output was computed
 * from NIST SP 800-38D section 7.1 by an independent Python implementation,
 * which also reproduces test cases 4 and 6. Every published vector here was
 * also checked against Python's hashlib and pyca/cryptography.
 * The error cases follow the RFC limits and the header documentation. That a
 * failed unwrap reports length 0 was observed on macOS 26.7.3 through
 * CCSymmetricKeyUnwrap, which returns the length this function leaves.
 *
 * Build and run from the repository root on an x86_64 host (on an aarch64
 * Linux host add -D__arm64__ so cc_unit is 64-bit):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/kdf_wrap_gcm_vectors.c \
 *     -o /tmp/kdf_wrap_gcm_vectors && /tmp/kdf_wrap_gcm_vectors
 */
#include <corecrypto/ccaes.h>
#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap_priv.h>
#include <corecrypto/cc_error.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void check(bool ok, const char *what)
{
	printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		failures++;
}

// Decodes a hex string into a newly allocated buffer (at least one byte, so
// an empty value is still a valid pointer).
static uint8_t *hex(const char *s, size_t *len)
{
	size_t n = strlen(s) / 2;
	uint8_t *out = malloc(n ? n : 1);
	for (size_t i = 0; i < n; i++)
		sscanf(s + 2 * i, "%2hhx", &out[i]);
	if (len)
		*len = n;
	return out;
}

static bool equal_hex(const uint8_t *got, size_t len, const char *want)
{
	size_t n;
	uint8_t *w = hex(want, &n);
	bool ok = n == len && memcmp(got, w, n) == 0;
	free(w);
	return ok;
}

static bool all_zero(const uint8_t *p, size_t len)
{
	for (size_t i = 0; i < len; i++)
		if (p[i])
			return false;
	return true;
}

static void test_hmac_long_key(void)
{
	uint8_t key[131], mac[64];
	memset(key, 0xaa, sizeof(key));
	static const struct { const char *name, *data, *sha256, *sha512; } cases[] = {
		{"RFC 4231 test case 6", "Test Using Larger Than Block-Size Key - Hash Key First",
		 "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		 "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"},
		{"RFC 4231 test case 7", "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
		 "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		 "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58"},
	};
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		char what[96];
		cchmac(ccsha256_di(), sizeof(key), key, strlen(cases[c].data), cases[c].data, mac);
		snprintf(what, sizeof(what), "HMAC-SHA256 %s", cases[c].name);
		check(equal_hex(mac, 32, cases[c].sha256), what);
		cchmac(ccsha512_di(), sizeof(key), key, strlen(cases[c].data), cases[c].data, mac);
		snprintf(what, sizeof(what), "HMAC-SHA512 %s", cases[c].name);
		check(equal_hex(mac, 64, cases[c].sha512), what);
	}
}

static void test_hkdf(void)
{
	static const struct {
		const char *name, *ikm, *salt, *info, *okm;
		bool sha1;
	} cases[] = {
		{"RFC 5869 A.1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
		 "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", false},
		{"RFC 5869 A.2",
		 "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		 "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		 "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		 "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87", false},
		{"RFC 5869 A.3 (no salt, no info)", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
		 "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", false},
		{"RFC 5869 A.4 (SHA-1)", "0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
		 "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896", true},
	};
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		const struct ccdigest_info *di = cases[c].sha1 ? ccsha1_di() : ccsha256_di();
		size_t ikm_len, salt_len, info_len, okm_len;
		uint8_t *ikm = hex(cases[c].ikm, &ikm_len), *salt = hex(cases[c].salt, &salt_len), *info = hex(cases[c].info, &info_len);
		free(hex(cases[c].okm, &okm_len));
		uint8_t okm[128];
		int rc = cchkdf(di, ikm_len, ikm, salt_len, salt, info_len, info, okm_len, okm);
		char what[96];
		snprintf(what, sizeof(what), "HKDF %s", cases[c].name);
		check(rc == CCERR_OK && equal_hex(okm, okm_len, cases[c].okm), what);
		free(ikm); free(salt); free(info);
	}

	// extract and expand separately give the RFC's PRK and the same OKM
	size_t ikm_len, salt_len, info_len;
	uint8_t *ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &ikm_len), *salt = hex("000102030405060708090a0b0c", &salt_len), *info = hex("f0f1f2f3f4f5f6f7f8f9", &info_len);
	uint8_t prk[32], okm[42];
	check(cchkdf_extract(ccsha256_di(), salt_len, salt, ikm_len, ikm, prk) == CCERR_OK
		&& equal_hex(prk, sizeof(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"), "HKDF-Extract gives the PRK of RFC 5869 A.1");
	check(cchkdf_expand(ccsha256_di(), sizeof(prk), prk, info_len, info, sizeof(okm), okm) == CCERR_OK
		&& equal_hex(okm, sizeof(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"), "HKDF-Expand gives the OKM of RFC 5869 A.1");

	// RFC 5869 section 2.3: L <= 255 * HashLen
	uint8_t *big = malloc(255 * 32 + 1);
	check(cchkdf_expand(ccsha256_di(), sizeof(prk), prk, 0, NULL, 255 * 32, big) == CCERR_OK, "HKDF-Expand of 255 * HashLen bytes succeeds");
	check(cchkdf_expand(ccsha256_di(), sizeof(prk), prk, 0, NULL, 255 * 32 + 1, big) != CCERR_OK, "HKDF-Expand of more than 255 * HashLen bytes fails");
	free(big); free(ikm); free(salt); free(info);
}

static void test_pbkdf2(void)
{
	static const struct {
		const char *password, *salt;
		size_t password_len, salt_len, iterations;
		const char *dk;
		bool sha1;
	} cases[] = {
		{"password", "salt", 8, 4, 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6", true},
		{"password", "salt", 8, 4, 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", true},
		{"password", "salt", 8, 4, 4096, "4b007901b765489abead49d926f721d065a429c1", true},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 24, 36, 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", true},
		{"pass\0word", "sa\0lt", 9, 5, 4096, "56fa6aa75548099dcc37d7f03425e0c3", true},
		{"passwd", "salt", 6, 4, 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783", false},
		{"Password", "NaCl", 8, 4, 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d", false},
	};
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		size_t dk_len;
		free(hex(cases[c].dk, &dk_len));
		uint8_t dk[64];
		int rc = ccpbkdf2_hmac(cases[c].sha1 ? ccsha1_di() : ccsha256_di(), cases[c].password_len, cases[c].password,
			cases[c].salt_len, cases[c].salt, cases[c].iterations, dk_len, dk);
		char what[96];
		snprintf(what, sizeof(what), "PBKDF2-HMAC-%s %zu iterations, %zu bytes (%s)", cases[c].sha1 ? "SHA1" : "SHA256",
			cases[c].iterations, dk_len, cases[c].sha1 ? "RFC 6070" : "RFC 7914");
		check(rc == CCERR_OK && equal_hex(dk, dk_len, cases[c].dk), what);
	}
	uint8_t dk[20];
	check(ccpbkdf2_hmac(ccsha1_di(), 8, "password", 4, "salt", 0, sizeof(dk), dk) != CCERR_OK, "PBKDF2 with zero iterations fails");
}

static void test_wrap(void)
{
	static const uint8_t default_iv[8] = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};
	static const struct { const char *name, *kek, *key, *wrapped; } cases[] = {
		{"4.1", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"},
		{"4.2", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d"},
		{"4.3", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7"},
		{"4.4", "000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff0001020304050607", "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2"},
		{"4.5", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff0001020304050607", "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1"},
		{"4.6", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f", "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21"},
	};
	const struct ccmode_ecb *enc = ccaes_ecb_encrypt_mode(), *dec = ccaes_ecb_decrypt_mode();
	for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		size_t kek_len, key_len, wrapped_len;
		uint8_t *kek = hex(cases[c].kek, &kek_len), *key = hex(cases[c].key, &key_len), *wrapped = hex(cases[c].wrapped, &wrapped_len);
		uint8_t out[48];
		char what[96];

		ccecb_ctx_decl(enc->size, ectx);
		enc->init(enc, ectx, kek_len, kek);
		size_t out_len = sizeof(out);
		int rc = ccwrap_auth_encrypt_withiv(enc, ectx, key_len, key, &out_len, out, default_iv);
		snprintf(what, sizeof(what), "RFC 3394 %s wrap", cases[c].name);
		check(rc == CCERR_OK && equal_hex(out, out_len, cases[c].wrapped), what);

		ccecb_ctx_decl(dec->size, dctx);
		dec->init(dec, dctx, kek_len, kek);
		out_len = sizeof(out);
		rc = ccwrap_auth_decrypt_withiv(dec, dctx, wrapped_len, wrapped, &out_len, out, default_iv);
		snprintf(what, sizeof(what), "RFC 3394 %s unwrap", cases[c].name);
		check(rc == CCERR_OK && equal_hex(out, out_len, cases[c].key), what);

		// a changed byte fails the integrity check, and nothing is returned
		wrapped[wrapped_len - 1] ^= 1;
		out_len = sizeof(out);
		memset(out, 0x55, sizeof(out));
		rc = ccwrap_auth_decrypt_withiv(dec, dctx, wrapped_len, wrapped, &out_len, out, default_iv);
		snprintf(what, sizeof(what), "RFC 3394 %s unwrap of changed data fails, clears the key and reports length 0", cases[c].name);
		check(rc != CCERR_OK && all_zero(out, wrapped_len - 8) && out_len == 0, what);
		free(kek); free(key); free(wrapped);
	}

	// another IV than the one used to wrap fails the integrity check
	size_t kek_len, wrapped_len;
	uint8_t *kek = hex("000102030405060708090a0b0c0d0e0f", &kek_len), *wrapped = hex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", &wrapped_len);
	static const uint8_t other_iv[8] = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa7};
	uint8_t out[48];
	ccecb_ctx_decl(dec->size, dctx);
	dec->init(dec, dctx, kek_len, kek);
	size_t out_len = sizeof(out);
	check(ccwrap_auth_decrypt_withiv(dec, dctx, wrapped_len, wrapped, &out_len, out, other_iv) != CCERR_OK, "RFC 3394 unwrap with another IV fails");

	// RFC 3394 key data is at least two 64-bit blocks, in whole blocks
	ccecb_ctx_decl(enc->size, ectx);
	enc->init(enc, ectx, kek_len, kek);
	uint8_t key[24] = {0};
	out_len = sizeof(out);
	check(ccwrap_auth_encrypt_withiv(enc, ectx, 8, key, &out_len, out, default_iv) != CCERR_OK, "wrapping one 64-bit block fails");
	out_len = sizeof(out);
	check(ccwrap_auth_encrypt_withiv(enc, ectx, 20, key, &out_len, out, default_iv) != CCERR_OK, "wrapping a partial block fails");
	out_len = 23;
	check(ccwrap_auth_encrypt_withiv(enc, ectx, 16, key, &out_len, out, default_iv) != CCERR_OK && out_len == 0, "wrapping into a too small buffer fails and reports length 0");
	out_len = sizeof(out);
	check(ccwrap_auth_decrypt_withiv(dec, dctx, 16, wrapped, &out_len, out, default_iv) != CCERR_OK, "unwrapping fewer than three blocks fails");
	out_len = 15;
	check(ccwrap_auth_decrypt_withiv(dec, dctx, wrapped_len, wrapped, &out_len, out, default_iv) != CCERR_OK, "unwrapping into a too small buffer fails");
	check(ccwrap_wrapped_size(16) == 24 && ccwrap_unwrapped_size(24) == 16 && ccwrap_unwrapped_size(4) == 0, "wrapped and unwrapped sizes");
	free(kek); free(wrapped);
}

static const char *K4 = "feffe9928665731c6d6a8f9467308308";
static const char *P4 = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
static const char *A4 = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

static const struct { const char *name, *key, *iv, *pt, *aad, *ct, *tag; } gcm_cases[] = {
	{"test case 2", "00000000000000000000000000000000", "000000000000000000000000", "00000000000000000000000000000000", "",
	 "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
	{"test case 4 (96-bit IV)", NULL, "cafebabefacedbaddecaf888", NULL, NULL,
	 "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47"},
	{"test case 5 (64-bit IV)", NULL, "cafebabefacedbad", NULL, NULL,
	 "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598", "3612d2e79e3b0785561be14aaca2fccb"},
	{"test case 6 (480-bit IV)", NULL, "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b", NULL, NULL,
	 "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5", "619cc5aefffe0bfa462af43c1699d050"},
	// not a published vector; see the comment at the top
	{"empty IV", NULL, "", NULL, NULL,
	 "a723d12b3ebff37b882445224ee18ad9cc171db1314486055084ad999f2979dfddc8a9273f05dda9df081b0ab170b5189f3727bafc8c1035a6ff3fe5", "f1ae1f9c2e6e254f6e68d1017fdbc597"},
};

static void test_gcm(void)
{
	const struct ccmode_gcm *enc = ccaes_gcm_encrypt_mode(), *dec = ccaes_gcm_decrypt_mode();
	for (size_t c = 0; c < sizeof(gcm_cases) / sizeof(gcm_cases[0]); c++) {
		size_t key_len, iv_len, pt_len, aad_len, ct_len, tag_len;
		uint8_t *key = hex(gcm_cases[c].key ? gcm_cases[c].key : K4, &key_len);
		uint8_t *iv = hex(gcm_cases[c].iv, &iv_len);
		uint8_t *pt = hex(gcm_cases[c].pt ? gcm_cases[c].pt : P4, &pt_len);
		uint8_t *aad = hex(gcm_cases[c].aad ? gcm_cases[c].aad : A4, &aad_len);
		uint8_t *ct = hex(gcm_cases[c].ct, &ct_len);
		uint8_t *expected_tag = hex(gcm_cases[c].tag, &tag_len);
		uint8_t out[64], tag[16];
		char what[128];
		const bool empty_iv = iv_len == 0;

		// one-shot encryption and decryption (the legacy variant for an empty IV)
		int (*one_shot)(const struct ccmode_gcm *, size_t, const void *, size_t, const void *, size_t, const void *, size_t, const void *, void *, size_t, void *)
			= empty_iv ? ccgcm_one_shot_legacy : ccgcm_one_shot;
		int rc = one_shot(enc, key_len, key, iv_len, iv, aad_len, aad, pt_len, pt, out, sizeof(tag), tag);
		snprintf(what, sizeof(what), "GCM %s: %s encrypts", gcm_cases[c].name, empty_iv ? "ccgcm_one_shot_legacy" : "ccgcm_one_shot");
		check(rc == CCERR_OK && equal_hex(out, ct_len, gcm_cases[c].ct) && equal_hex(tag, sizeof(tag), gcm_cases[c].tag), what);

		memcpy(tag, expected_tag, sizeof(tag));
		rc = one_shot(dec, key_len, key, iv_len, iv, aad_len, aad, ct_len, ct, out, sizeof(tag), tag);
		snprintf(what, sizeof(what), "GCM %s: one-shot decryption", gcm_cases[c].name);
		check(rc == CCERR_OK && equal_hex(out, pt_len, gcm_cases[c].pt ? gcm_cases[c].pt : P4), what);

		memcpy(tag, expected_tag, sizeof(tag));
		tag[0] ^= 1;
		rc = one_shot(dec, key_len, key, iv_len, iv, aad_len, aad, ct_len, ct, out, sizeof(tag), tag);
		snprintf(what, sizeof(what), "GCM %s: one-shot decryption with a changed tag fails", gcm_cases[c].name);
		check(rc != CCERR_OK, what);

		// the incremental interface with ccgcm_set_iv_legacy, the IV given in two parts
		ccgcm_ctx_decl(ccgcm_context_size(enc), ctx);
		rc = ccgcm_init(enc, ctx, key_len, key);
		if (rc == CCERR_OK)
			rc = ccgcm_set_iv_legacy(enc, ctx, iv_len / 2, iv);
		if (rc == CCERR_OK)
			rc = ccgcm_set_iv_legacy(enc, ctx, iv_len - iv_len / 2, iv + iv_len / 2);
		if (rc == CCERR_OK)
			rc = ccgcm_aad(enc, ctx, aad_len, aad);
		if (rc == CCERR_OK)
			rc = ccgcm_update(enc, ctx, pt_len, pt, out);
		if (rc == CCERR_OK)
			rc = ccgcm_finalize(enc, ctx, sizeof(tag), tag);
		snprintf(what, sizeof(what), "GCM %s: ccgcm_set_iv_legacy and the incremental interface", gcm_cases[c].name);
		check(rc == CCERR_OK && equal_hex(out, ct_len, gcm_cases[c].ct) && equal_hex(tag, sizeof(tag), gcm_cases[c].tag), what);
		ccgcm_ctx_clear(ccgcm_context_size(enc), ctx);

		free(key); free(iv); free(pt); free(aad); free(ct); free(expected_tag);
	}

	// ccgcm_one_shot requires an IV; only the legacy variant accepts an empty one
	size_t key_len;
	uint8_t *key = hex(K4, &key_len);
	uint8_t pt[16] = {0}, out[16], tag[16];
	check(ccgcm_one_shot(enc, key_len, key, 0, "", 0, NULL, sizeof(pt), pt, out, sizeof(tag), tag) != CCERR_OK, "ccgcm_one_shot with an empty IV fails");
	free(key);
}

int main(void)
{
	test_hmac_long_key();
	test_hkdf();
	test_pbkdf2();
	test_wrap();
	test_gcm();
	printf(failures ? "FAILED (%d)\n" : "ALL PASSED\n", failures);
	return failures != 0;
}
