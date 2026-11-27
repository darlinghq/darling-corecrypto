/*
 * Copyright (c) 2026 Lubos Dolezel
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
 * Finite field Diffie-Hellman, modular exponentiation and PKCS #7 padding:
 * - ccdh_init_gp, ccdh_import_pub, ccdh_compute_key, ccdh_compute_shared_secret
 *   and cczp_power with the test data of RFC 5114 appendix A.1 to A.3
 *   (the published private values, public values and shared secrets);
 * - the RFC 2409 / RFC 3526 MODP groups: their primes against the
 *   hexadecimal values printed in the RFCs (group 2, 5 and 14 here; all seven
 *   are checked by scripts/generate-modp-groups.py --check), key generation and
 *   agreement, and rejection of the peer keys 0, 1, p - 1 and p
 *   (NIST SP 800-56A section 5.6.2.3);
 * - ccz_expmod against Python's pow() (exponent 0, modulus 1, even moduli,
 *   bases above the modulus, operands up to 4096 bits);
 * - ccpad_pkcs7_*: NIST SP 800-38A F.2.1 CBC-AES128 plus one block of
 *   padding (that block computed with pyca/cryptography), round trips for every
 *   length from 0 to 33 in CBC and ECB, and ccpad_pkcs7_decode, whose
 *   behaviour on invalid padding was observed on macOS 10.14.4 and 26.7.3
 *   (see the QUIRK comment in src/ccpad.c).
 *
 * Build and run from the repository root (on an aarch64 Linux host add
 * -D__arm64__ so cc_unit is 64-bit; add -m32 for 32-bit units; ccmd4.c is left
 * out because it does not build for 32-bit Linux):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | grep -v ccmd4 | tr -d '\t ' | sort -u) tests/standalone/dh_modexp_pkcs7.c \
 *     -o /tmp/dh_modexp_pkcs7 && /tmp/dh_modexp_pkcs7
 */
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_gp.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccz.h>
#include <corecrypto/cczp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
#define CHECK(cond, what) do { if (!(cond)) { printf("FAIL line %d: %s: %s\n", __LINE__, what, #cond); failures++; } } while (0)

static size_t from_hex(const char *hex, uint8_t *out)
{
	size_t n = strlen(hex) / 2;
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		sscanf(hex + 2 * i, "%2x", &v);
		out[i] = (uint8_t)v;
	}
	return n;
}

static int same_integer(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
	while (an && !*a) { a++; an--; }
	while (bn && !*b) { b++; bn--; }
	return an == bn && memcmp(a, b, an) == 0;
}

/* RFC 5114 appendix A: p, g, q, xA, yA, xB, yB, Z */
static const struct {
	const char *name, *p, *g, *q, *xa, *ya, *xb, *yb, *z;
} rfc5114[] = {
	{ "RFC 5114 A.1 (1024-bit p)",
	  "b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c69a6a9dca52d23b616073e28675a23d189838ef1e2ee652c013ecb4aea906112324975c3cd49b83bfaccbdd7d90c4bd7098488e9c219a73724effd6fae5644738faa31a4ff55bccc0a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708df1fb2bc2e4a4371",
	  "a4d1cbd5c3fd34126765a442efb99905f8104dd258ac507fd6406cff14266d31266fea1e5c41564b777e690f5504f213160217b4b01b886a5e91547f9e2749f4d7fbd7d3b9a92ee1909d0d2263f80a76a6a24c087a091f531dbf0a0169b6a28ad662a4d18e73afa32d779d5918d08bc8858f4dcef97c2a24855e6eeb22b3b2e5",
	  "f518aa8781a8df278aba4e7d64b7cb9d49462353",
	  "b9a3b3ae8fefc1a2930496507086f8455d48943e",
	  "2a853b3d92197501b9015b2deb3ed84f5e021dcc3e52f109d3273d2b7521281cbabe0e76ff5727fa8acce26956ba9a1fca26f20228d8693feb10841d84a7360054ece5a7f5b7a61ad3dfb3c60d2e43106d8727da37df9cce95b478755d06bcea8f9d45965f75a5f3d1df3701165fc9e50c4279ceb07f989540ae96d5d88ed776",
	  "9392c9f9eb6a7a6a9022f7d83e7223c6835bbdda",
	  "717a6cb053371ff4a3b932941c1e5663f861a1d6ad34ae66576dfb98f6c6cbf9ddd5a56c7833f6bcfdff095582ad868e440e8d09fd769e3ceccdc3d3b1e4cfa057776caaf9739b6a9fee8e7411f8d6dac09d6a4edb46cc2b5d5203090eae6126311e53fd2c14b574e6a3109a3da1be41bdceaa186f5ce06716a2b6a07b3c33fe",
	  "5c804f454d30d9c4df85271f93528c91df6b48ab5f80b3b59caac1b28f8acba9cd3e39f3cb614525d9521d2e644c53b807b810f340062f257d7d6fbfe8d5e8f072e9b6e9afda9413eafb2e8b0699b1fb5a0caceddeaead7e9cfbb36ae2b420835bd83a19fb0b5e96bf8fa4d09e345525167ecd9155416f46f408ed31b63c6e6d" },
	{ "RFC 5114 A.2 (2048-bit p)",
	  "ad107e1e9123a9d0d660faa79559c51fa20d64e5683b9fd1b54b1597b61d0a75e6fa141df95a56dbaf9a3c407ba1df15eb3d688a309c180e1de6b85a1274a0a66d3f8152ad6ac2129037c9edefda4df8d91e8fef55b7394b7ad5b7d0b6c12207c9f98d11ed34dbf6c6ba0b2c8bbc27be6a00e0a0b9c49708b3bf8a317091883681286130bc8985db1602e714415d9330278273c7de31efdc7310f7121fd5a07415987d9adc0a486dcdf93acc44328387315d75e198c641a480cd86a1b9e587e8be60e69cc928b2b9c52172e413042e9b23f10b0e16e79763c9b53dcf4ba80a29e3fb73c16b8e75b97ef363e2ffa31f71cf9de5384e71b81c0ac4dffe0c10e64f",
	  "ac4032ef4f2d9ae39df30b5c8ffdac506cdebe7b89998caf74866a08cfe4ffe3a6824a4e10b9a6f0dd921f01a70c4afaab739d7700c29f52c57db17c620a8652be5e9001a8d66ad7c17669101999024af4d027275ac1348bb8a762d0521bc98ae247150422ea1ed409939d54da7460cdb5f6c6b250717cbef180eb34118e98d119529a45d6f834566e3025e316a330efbb77a86f0c1ab15b051ae3d428c8f8acb70a8137150b8eeb10e183edd19963ddd9e263e4770589ef6aa21e7f5f2ff381b539cce3409d13cd566afbb48d6c019181e1bcfe94b30269edfe72fe9b6aa4bd7b5a0f1c71cfff4c19c418e1f6ec017981bc087f2a7065b384b890d3191f2bfa",
	  "801c0d34c58d93fe997177101f80535a4738cebcbf389a99b36371eb",
	  "22e62601dbffd06708a680f747f361f76d8f4f721a0548e483294b0c",
	  "1b3a63451bd886e699e67b494e288bd7f8e0d370badda7a0efd2fde7d8f66145cc9f280419975eb808877c8a4c0c8e0bd48d4a5401eb1e8776bfeee134c03831ac273cd9d635ab0ce006a42a887e3f52fb8766b650f38078bc8ee8580cefe243968cfc4f8dc3db084554171d41bf2e861b7bb4d69dd0e01ea387cbaa5ca672afcbe8bdb9d62d4ce15f17dd36f91ed1eedd65ca4a06455cb94cd40a52ec360e84b3c926e22c4380a3bf309d56849768b7f52cfdf655fd053a7ef706979e7e5806b17dfae53ad2a5bc568ebb529a7a61d68d256f8fc97c074a861d827e2ebc8c6134553115b70e7103920aa16d85e52bcbab8d786a68178fa8ff7c2f5c71648d6f",
	  "4ff3bc96c7fc6a6d71d3b363800a7cdfef6fc41b4417ea15353b7590",
	  "4dcee992a9762a13f2f83844ad3d77ee0e31c9718b3db6c2035d3961182c3e0ba247ec4182d760cd48d99599970622a1881bba2dc822939c78c3912c6661fa5438b20766222b75e24c2e3ad0c7287236129525ee15b5dd7998aa04c4a9696cacd7172083a97a81664ead2c479e444e4c0654cc19e28d7703cee8dacd6126f5d665ec52c67255db92014b037eb621a2ac8e365de071ffc1400acf077a12913dd8de89473437ab7ba346743c1b215dd9c12164a7e4053118d199bec8ef6fc561170c84c87d10ee9a674a1fa8ffe13bdfba1d44de48946d68dc0cdd777635a7ab5bfb1e4bb7b856f96827734c184138e915d9c3002ebce53120546a7e2002142b6c",
	  "34d9bddc1b42176c313fea034c21034d074a6313bb4ecdb3703fff424567a46bdf75530ede0a9da5229de7d76732286cbc0f91da4c3c852fc099c679531d94c78ab03d9decb0a4e4ca8b2bb4591c4021cf8ce3a20a541d33994017d0200ae2c9516e2ff5145779269e862b0fb474a2d56dc31ed569a7700b4c4ab16b22a45513531ef523d71212077b5a169bdeffad7ad9608284c7795b6d5a5183b87066de17d8d671c9ebd8ec89544d45ec061593d442c62ab9ce3b1cb9943a1d23a5ea3bcf21a01471e67e003e7f8a69c728be490b2fc88cfeb92db6a215e5d03c17c464c9ac1a46e203e13f952995fb03c69d3cc47fcb510b6998ffd3aa6de73cf9f63869" },
	{ "RFC 5114 A.3 (2048-bit p)",
	  "87a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a1597",
	  "3fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659",
	  "8cf83642a709a097b447997640129da299b1a47d1eb3750ba308b0fe64f5fbd3",
	  "0881382cdb87660c6dc13e614938d5b9c8b2f248581cc5e31b35454397fce50e",
	  "2e9380c8323af97545bc4941deb0ec3742c62fe0ece824a6abdbe66c59bee0242911bfb967235ceba35ae13e4ec752be630b92dc4bde2847a9c62cb8152745421fb7eb60a63c0fe9159fcce726ce7cd8523d7450667ef840e4919121eb5f01c8c9b0d3d648a93bfb75689e8244ac134af544711ce79a02dcc34226684780dddcb498594106c37f5bc79856487af5ab022a2e5e42f09897c1a85a11ea0212af04d9b4cebc937c3c1a3e15a8a0342e337615c84e7fe3b8b9b87fb1e73a15af12a30d746e06dfc34f290d797ce51aa13aa785bf6658aff5e4b093003cbeaf665b3c2e113a3a4e905269341dc0711426685f4ef37e868a8126ff3f2279b57ca67e29",
	  "7d62a7e3ef36de617b13d1afb82c780d83a23bd4ee6705645121f371f546a53d",
	  "575f0351bd2b1b817448bdf87a6c362c1e289d3903a30b9832c5741fa250363e7acbc7f77f3dacbc1f131add8e03367eff8fbbb3e1c5784424809b25afe4d2262a1a6fd2fab64105ca30a674e07f7809852088632fc049233791ad4edd083a978b883ee618bc5e0dd047415f2d95e683cf14826b5fbe10d3ce41c6c120c78ab20008c698bf7f0bcab9d7f407bed0f43afb2970f57f8d12043963e66ddd320d599ad9936c8f44137c08b180ec5e985cebe186f3d549677e80607331ee17af3380a725b0782317d7dd43f59d7af9568a9bb63a84d365f92244ed120988219302f42924c7ca90b89d24f71b0ab697823d7deb1aff5b0e8e4a45d49f7f53757e1913",
	  "86c70bf8d0bb81bb01078a17219cb7d27203db2a19c877f1d1f19fd7d77ef22546a68f005ad52dc84553b78fc60330be51ea7c0672cac1515e4b35c047b9a551b88f39dc26da14a09ef74774d47c762dd177f9ed5bc2f11e52c879bd95098504cd9eecd8a8f9b3efbd1f008ac5853097d9d1837f2b18f77cd7be01af80a7c7b5ea3ca54cc02d0c116fee3f95bb87399385875d7e86747e676e728938acbff7098e05be4dcfb24052b83aeffb14783f029adbde7f53fae92084224090e007cee94d4bf2bace9ffd4b57d2af7c724d0caa19bf0501f6f17b4aa10f425e3ea76080b4b9d6b3cefea115b2ceb8789bb8a3b0ea87febe63b6c8f846ec6db0c26c5d7c" },
};

static void test_rfc5114(void)
{
	for (size_t t = 0; t < sizeof(rfc5114) / sizeof(rfc5114[0]); t++) {
		const char *name = rfc5114[t].name;
		uint8_t buf[512];
		size_t len = from_hex(rfc5114[t].p, buf);
		const cc_size n = ccn_nof_size(len);
		cc_unit p[n], g[n], xa[n], ya[n], z[n], r[n];

		ccn_read_uint(n, p, len, buf);
		len = from_hex(rfc5114[t].g, buf);
		ccn_read_uint(n, g, len, buf);

		ccdh_gp *storage = calloc(1, ccdh_gp_size(ccn_sizeof_n(n)));
		ccdh_gp_t gp = (ccdh_gp_t)storage;
		ccdh_const_gp_t cgp = (ccdh_const_gp_t)(const ccdh_gp *)storage;
		CHECK(ccdh_init_gp(gp, n, p, g, 0) == 0, name);
		CHECK(ccdh_gp_n(cgp) == n, name);

		/* yA = g^xA mod p */
		len = from_hex(rfc5114[t].xa, buf);
		ccn_read_uint(n, xa, len, buf);
		len = from_hex(rfc5114[t].ya, buf);
		ccn_read_uint(n, ya, len, buf);
		cczp_power(CCDH_GP_ZP(gp), r, g, xa);
		CHECK(memcmp(r, ya, ccn_sizeof_n(n)) == 0, name);

		/* A's full key (y then x, as ccdh.h lays it out) and B's public key */
		ccdh_full_ctx *a = calloc(1, ccdh_full_ctx_size(ccn_sizeof_n(n)));
		ccdh_ctx_init(cgp, (ccdh_pub_ctx_t)a);
		memcpy(ccdh_ctx_y(a), ya, ccn_sizeof_n(n));
		memcpy(ccdh_ctx_y(a) + n, xa, ccn_sizeof_n(n));

		ccdh_pub_ctx *b = calloc(1, ccdh_pub_ctx_size(ccn_sizeof_n(n)));
		len = from_hex(rfc5114[t].yb, buf);
		CHECK(ccdh_import_pub(cgp, len, buf, (ccdh_pub_ctx_t)b) == 0, name);

		uint8_t expected[512], secret[512];
		size_t elen = from_hex(rfc5114[t].z, expected);
		CHECK(ccdh_compute_key((ccdh_full_ctx_t)a, (ccdh_pub_ctx_t)b, z) == 0, name);
		ccn_read_uint(n, r, elen, expected);
		CHECK(memcmp(z, r, ccn_sizeof_n(n)) == 0, name);

		size_t slen = sizeof(secret);
		CHECK(ccdh_compute_shared_secret((ccdh_full_ctx_t)a, (ccdh_pub_ctx_t)b, &slen, secret, ccrng(NULL)) == 0, name);
		CHECK(same_integer(secret, slen, expected, elen) && secret[0] != 0, name);

		/* the order is known here: y^q == 1 holds for yB */
		len = from_hex(rfc5114[t].q, buf);
		cc_unit q[n];
		ccn_read_uint(n, q, len, buf);
		cczp_power(CCDH_GP_ZP(gp), r, ccdh_ctx_y(b), q);
		CHECK(r[0] == 1 && ccn_bitlen(n, r) == 1, name);

		free(a);
		free(b);
		free(storage);
	}
}

/* the primes as RFC 2409 section 6.2 and RFC 3526 sections 2 and 3 print them */
static const char rfc2409_group2[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
	"8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
	"0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
static const char rfc3526_group5[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
	"8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
	"0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
	"1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
	"F1746C08CA237327FFFFFFFFFFFFFFFF";
static const char rfc3526_group14[] =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879"
	"8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B"
	"0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA4836"
	"1C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
	"F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6"
	"955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

static void test_modp_group(const char *name, ccdh_const_gp_t gp, const char *prime_hex)
{
	uint8_t buf[1024], out[1024];
	size_t plen = 0;
	for (size_t i = 0; prime_hex[i]; i += 2) {
		unsigned v;
		sscanf(prime_hex + i, "%2X", &v);
		buf[plen++] = (uint8_t)v;
	}
	const cc_size n = ccdh_gp_n(gp);
	CHECK(ccdh_ccn_size(gp) == plen, name);
	ccn_write_uint(n, ccdh_gp_prime(gp), plen, out);
	CHECK(memcmp(out, buf, plen) == 0, name);
	CHECK(ccdh_gp_g(gp)[0] == 2 && ccn_bitlen(n, ccdh_gp_g(gp)) == 2, name);

	struct ccrng_state *rng = ccrng(NULL);
	ccdh_full_ctx *a = calloc(1, ccdh_full_ctx_size(ccn_sizeof_n(n)));
	ccdh_full_ctx *b = calloc(1, ccdh_full_ctx_size(ccn_sizeof_n(n)));
	ccdh_pub_ctx *pub = calloc(1, ccdh_pub_ctx_size(ccn_sizeof_n(n)));
	CHECK(ccdh_generate_key(gp, rng, (ccdh_full_ctx_t)a) == 0, name);
	CHECK(ccdh_generate_key(gp, rng, (ccdh_full_ctx_t)b) == 0, name);
	CHECK(ccdh_export_pub_size((ccdh_pub_ctx_t)a) == plen, name);

	/* y = g^x */
	cc_unit r[n];
	cczp_power(CCDH_CONST_GP_T_ZP(gp), r, ccdh_gp_g(gp), ccdh_ctx_y(a) + n);
	CHECK(memcmp(r, ccdh_ctx_y(a), ccn_sizeof_n(n)) == 0, name);

	uint8_t sa[1024], sb[1024];
	size_t la = sizeof(sa), lb = sizeof(sb);
	ccdh_export_pub((ccdh_pub_ctx_t)b, out);
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == 0, name);
	CHECK(ccdh_compute_shared_secret((ccdh_full_ctx_t)a, (ccdh_pub_ctx_t)pub, &la, sa, rng) == 0, name);
	ccdh_export_pub((ccdh_pub_ctx_t)a, out);
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == 0, name);
	CHECK(ccdh_compute_shared_secret((ccdh_full_ctx_t)b, (ccdh_pub_ctx_t)pub, &lb, sb, rng) == 0, name);
	CHECK(la == lb && memcmp(sa, sb, la) == 0 && sa[0] != 0, name);

	/* a secret buffer that is too small */
	la = 8;
	CHECK(ccdh_compute_shared_secret((ccdh_full_ctx_t)a, (ccdh_pub_ctx_t)pub, &la, sa, rng) != 0, name);

	/* peer keys outside [2, p - 2] */
	memset(out, 0, plen);
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == CCDH_SAFETY_CHECK, name);
	out[plen - 1] = 1;
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == CCDH_SAFETY_CHECK, name);
	out[plen - 1] = 2;
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == 0, name);
	memcpy(out, buf, plen);
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == CCDH_SAFETY_CHECK, name);
	out[plen - 1] -= 1;
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == CCDH_SAFETY_CHECK, name);
	out[plen - 1] -= 1;
	CHECK(ccdh_import_pub(gp, plen, out, (ccdh_pub_ctx_t)pub) == 0, name);
	/* longer than p */
	memset(out, 0xff, plen + 1);
	CHECK(ccdh_import_pub(gp, plen + 1, out, (ccdh_pub_ctx_t)pub) != 0, name);

	/* an invalid key that skipped ccdh_import_pub is still refused */
	memset(ccdh_ctx_y(pub), 0, ccn_sizeof_n(n));
	ccdh_ctx_y(pub)[0] = 1;
	la = sizeof(sa);
	CHECK(ccdh_compute_shared_secret((ccdh_full_ctx_t)a, (ccdh_pub_ctx_t)pub, &la, sa, rng) == CCDH_SAFETY_CHECK, name);

	free(a);
	free(b);
	free(pub);
}

/* Python: hex(pow(base, exponent, modulus)) */
static const struct { const char *name, *base, *exponent, *modulus, *result; } modexp[] = {
	{ "exponent 0", "03", "00", "0b", "01" },
	{ "0^0 mod 7", "00", "00", "07", "01" },
	{ "0^5 mod 7", "00", "05", "07", "00" },
	{ "modulus 1", "05", "03", "01", "00" },
	{ "modulus 1, exponent 0", "05", "00", "01", "00" },
	{ "modulus 2", "07", "03", "02", "01" },
	{ "even modulus 1000", "02", "0a", "03e8", "18" },
	{ "modulus 2^64", "03", "ffffffffffffffff", "010000000000000000", "aaaaaaaaaaaaaaab" },
	{ "base above modulus", "0100000000000000000000000000000000000000000000003039", "010001", "7fffffffffffffffffffffffffffffff", "76d4157f7540a1cab5b037e6a5759679" },
	{ "base equal to modulus", "7fffffffffffffffffffffffffffffff", "03", "7fffffffffffffffffffffffffffffff", "00" },
	{ "exponent above modulus", "07", "1000000000000000000000000000000000000000000000000000000000000000000000000001", "1fffffffffffffff", "1fffffffffffffce" },
	{ "random 64-bit odd modulus, 64-bit exponent", "3fd9677c3da8902c", "effc5347cbbe301d", "ebc5e73155622553", "5005d37d5e0ab120" },
	{ "random 521-bit odd modulus, 521-bit exponent", "039fbce73c2decbfad72feec3eb77e79214bc8d1d2fdcfc1f76ae84eadeeff756db18beeae470443f7556804749bcaebba4d19f77c4eb7e1def3f5df29b4b6623bbd641fb3296c68ae39be", "010aee86e4fa96d9e1a73e18d61c100eef2b6d9ba14f9d0a59215187e987a2be76879ffaa1166e70a2e5393611b32acc23ff831f38e37cccd4f101c4f6ddaf7b344b", "016559cfb79310927a1467ce8c1db955b0e0c7cabd9d948324910b46e32caad71fa4de80502c3374f8c628a1a8fe0af1afa0b7ed474ed6bc2dac3e18558689a5d3d7", "1a6e83f9fd48cc1c958b5459144693015555ca2b7eea2c1381ea26fb746a3a49b60eb5ff1fb597bbd56875046599cbc33aea95866f52a44fa2c4fdee7ebfd59e90" },
	{ "random 1024-bit odd modulus, 160-bit exponent", "c08d7d693e4b1e1b6cbb3eb63d381a030ba8f1e1d2f74923852f55c9f22e7cd93c69f5f6e7c9ddda0f80cf65870dd96baf7ea1d2db8cf2a9bff4d51aca5fe81c3b6a8d462d4f847e5b62747e0d585bde65eb3f78857d42e15dcfe9acf4b41dfebf0af929b6daf040976cb74e7fe03bd3d7aa5ae4a9ef7b5950e48223f475302e", "f61d45f8756ebe893ae6c7b63b8b4b7867e4fb19", "9b36ab93510d12450cced9aa09e92e409537fc2c87a89f94b7ba64d5207e36c9c3d9437742a19b3eaccf74fcb55aff78a86e59f3586a24ef1d3ca4eda4193ecf3cccfc09935c2d01372c8fa644757f2e628714d6fb72f63039ddb4694b797c486cccbf37aa27d67e0dfa3e72cd5792c16af90c9fbda4b8670cc457fb8dc838ed", "4ef47dce0c5979c81f5e8fc4567e9075ea692527c7818176fef2a302b9074377b2eeaa45a80f8bd99d8cadc8ea6e53d721c47859f9233c9558aee18dd826fe775d0029e270de34090f5aa8cef9cc79abc9ad66b9a6e26f0f26e752b0aa91b3eee16dbe41544b98473efb21768bd43a8ce454542804579b576b6cf0eed2c2c36f" },
	{ "random 2048-bit odd modulus, 2048-bit exponent", "4b9d1c148cc1b6c91c5770213d848ba918f34368af9be07851107b2aa89f49894ca25fe1fe7117f7d428096cb2562a075a0942be1386bb0fdb6d38575388a793a2a4d8da02aa3be7eccd53a0dfd71030dcae5a8bbfaa1bb0a53ca7d5857ceb836e85ca8bf3ea129d263d70531af8ab2ca4ff8542e38dcefcd508705c45fa178d10e16a79bc894e3fb9a922c5160f8976118955cca7a0eaad5a3b0036bfea3e4836cb11c4e9cd7540acc2e54975880d2ef8770afec41912ac7a9b1df7149be358646355fece140a421a0bbcb98562de2864740fc86bc0527777757be04cbb4ee07a285c24d9090d596cd2e51d8fefca51c085016a0639991e7a14134ad7a592eb8551e8a08cd630b989ad28a1628eaa60aed9577da99b7df3682377ad873e7623d95736523b9d98e04ea5bf10c4e993ccc5fdd9fc71e2457494881571099ce81166d88d85c41b269aa68ce40a1dbdeb51bd4f36c3d22870097353910c9e0ee3786b224b5ef72cb518904ac9c1f239aa8b4353cd965cffca", "bf9eff31ea4e521d87908d3fcc5dfb70d5a5ee2995f5f4070e6aba2fe8304f5afc5d143ee832c404bff0f297fb4471f07b704e917a841239eaa245c9dfafa2d041c945be14f1557beb59bc84fffccc1046fc054bf90f90151a32ab1ffca0ccab8c71e925bf609746220347f871a3749f7405b92f0a5e7d68df1a0748217c89725019d43a8caee26e2903baba4ea5e386e6ebbed5e79e478d9bd8bb231b79a7688002d29cbe6d2018734561695780b370e003838cc2b8b093ecedc7a4055bd3e1c22450325b34cb3ba05289541c050ab3f74e298eecb26e07a7ca6fa6b2f7c77608058029a35ac380327e7696516238f0bab1b9bea45e7f217271991775df484d", "b4d214cbdc8653c5e8b8ef6ef24017f9c3f6b57e3f20cee9427e3f5c4c4b2ad0b7871204350691eb2a4d562229e9ae482a29204d0c158ac3a32ffbba04aaebd3f311faa8edbfd4b03527dd52adc3a7853997dabf3a1d80468b094f74a5ce61d387fc9fc0194c9bf41bb6ae1ac91df20e7379bac651bffe8f01c7114905e945e7b97f14d78e445fdd8a8d92585d4ac6a7eaf067beb8694b398a30ffbe775db9cf86ea9ec607754b5fce20cefe8cfa5ce819a4873e0fab996afb0205d18d5ee028466fa111c7e1f03e6016b3af1306c5e4ca97ba308ef9867e3a712082bd8b4eba6d7b755c0be938b7ca16677c2e486a6875832fcd5f338153d763382c94fe4ba7", "59a710af8c427d53cd4358a3c5ec1a0b4a62aa43c9dc88c32ff1e96425a697d694d50c3b4567a03a052f3858ba27fb3c36ca1e69467cbde64861e7e43c34d52ecabb7a77b4c51b2d3d58776406d7a3a3c7021f1f492f308a1044ccd0e6e300f8eda6a0316bccf8d6ef06121345840f6b56ef3032e3f46b060fd95dbd7f82cf70bc5a95231f5f08e6b39b760efdd5d29e51f777ac207165789819d3fc346a6004e35a1e2ce7cace6f9c207d0253e4e501de1576d8551d42057c36fc13802137548b124cf359b9f446ed0e704a0bb9fdb7d915ed50417be8251962ef8bb83150af0754a1f94d1db63fc2fa09024ab54e90ccdd20fcfc4f37355aa839bb96a21cba" },
	{ "random 4096-bit odd modulus, 4096-bit exponent", "876234241daf870b99864ea2ddde388cc61cf77a2258ff961d69c44ed900e368f0d0eec5b62cba1b4ade7d2a184d8f28fdff9ace3521dcf7baea2279ae33e0d44281c1c16b11cd4d144a3334f50002d4d51df5315e3efc3c4428429e746a51adf8ab01da37157d26a09fc3fa8bf5a75cf751bf99ea254ab85ea7c6654daf40a0bc72966bc8c9faa122915bd289ffa227d7470861a482c26cf607b88a6c9d3aa38c543722d9e7d74f887acc06449ba51fd6fbd1ab90451d554fb879aed5614bf2ad5d67da88ad1b087c648bb19aa9aa7ae885cfc7074d9dc1fc06126c40fda5237392fd7478b0323c767dcdeadaf5190423162353eb2215cc62c29355e774fb52b8d76fee1112700bf656a5f52bf861d66bf6815cd01c6535ecda2a6ed6e350fa2c1b40eb245d0acd25300d46a3e261c9e31dbc187beb0000fa3fd8327689ed9c2ea259030b9e53547e4d2438be17f08d00eb8706950fee133c1a3fe3d018cbe16b043600fd92b9ffda138e20ace509109c88a7d99aba2bd994612befe62c57ccbfa6296432b9b90847c6a22ac2e914277712819d26d4fe7d281034f26d2ce968c99cc8cf464a4c39e993b7583ea5c8e6859961f8510be33a68006cb99f376b5b6b5ce5564bfd9d665bcd0dd4046035b4462677e65c6ee92927cdb75afc6b51a87a0fe5e7e0abc907894d671c84c855fb39bb1f24ce00e1b587e532e44059e268", "c03859c15d22735d699388a654059c8417ed93c3c041f4cf7063cd7d63e62b2af72a842e6d4be113cb9d34140cef85f6c81896973e47f8ecdddd1d6b5938b8dbf11f0d0f2852f7eb337776ba57ce3c3cc034bc330eb146bb730bef698389e68c3565ac1014b08789a5c5b283e9ac24e224c46da87e89dfc478431001b61b5ee072cf26841cac4baaab036d1cca5e74725097c91db501adea09db3f736f13fe32f3ee113c20d8fff20a19c40621112aeb3ba817fc10a815951a7f2e47ec31b97ebb0bc8db5c44c9e8db1fa607b1bc7e918f067b7a59c361ecf0d0ea210634c57ff42a5dd151d6bea951b8d739816936062a0b6aad0cd1ca0c8bd7fb2df7180aab07e1b28a2507b53645e479f42dd0331f0f8e83382c72fad4189b7f1ce5a1d9b9716426644a55b19ab1288b6e554be1f65b7c747975f13cc29356a836ff05845f5bcaa8e6d438bf8b3a20842a6685021823c4ef305ef002d960745262be1b5a0490536b514b95f909fee2fb88049b87023a994669678edf8e0b38e155c29e0fee05dad88b123b9f89757a3d889ee949d9eaffa20c7597acab0f7c4aec7acf04119f603a773057cba80d5da5ca2ce51ffa04000fd32a765fd5f3dc1682b447bdf877a85691ce19005580726abbdde2c3706d1e1cc012f4219f51fa629a0df6056d35f9644ed1d90eeeaed0fd9e0e92a8a40a31e599cd8490e1e3aa42e9941a8b82", "f822ee72f13313a7ee64dd8c5eedef381ace1f53abc8959c22d353485bcacb163bcc419d1b3f2efb38766109f5c892be844a481b4ffb256902d7f30e012b6214791611f3b1ce19b59c5fec77ce31dc51b41e1e23e066b654c0ad01fda1f122d8cd1458cf11d7e2d27854d17117bdfbf6e0873c2c063179f3f10b6d186321047f2911c79ece1b8aa029019064e9f71d9d762bdd38cee47bd16f41ec4651a4f0f44277f6efe5287c98a9265524a6b6792d6f15de57987a2a59e8c89bde1b6a775162a401a2723f7d410adb00d5accf02ec740fb90599296f9ed87aacb07970c93b2fbc009724f96b8da4021c6d55cafeac30e52252775b4323f1d32d2ac22d726a1f33a0052a84c8cee985acd11351fc910a4730b81610e892fe7b2aa1cc4d3cc4231d4715c31c22f019ad0c01dd948ddb3953127360b35e7a64e203624125b867e87496cc9d61692462ada92a4d3e3a95ac00b5d1fea69df74ba1c55cb42588af63ab1d687ecce9484fe5844f0201ad5532f715810862b0a4c48a68d0e0b9aee206494998638660bc891eb6cd251b07c77c88cba689336bd3e1c79512aeec2a19891ed82207ecf91b6e38ff7057c40a6f53d2ddce8e6d0cd550a0ede02becd9391e9e4de80c8a3ac5f5964439a5250d28fa8b364b3fba0657f1bb7bb5c26c70b2ebd377523bb38627aaa88a3506e70fcbb4a573f6d497808928259c8b0547b885", "49530b5fbb01f1d92a3c80935859f85073525b6c3daad55264404b6553a0bf5898484a2f3305b7eed1d109f184e1b8323dbfa19e48092356bf925383318bd7e7d4dcfcaa188609f2ccbba2d55e8e20e6bdf37d2b9b3530f2505250df41e417d91501fe57bdbf8a3f6d9c25af959e9e868671493383b21846f37e1b4c0972f583011f6acf57718ce51b4946549ede01e14f31b5ad8245535bcc8cb63e119f996501c22929a1b8be95da18f63fa7e0b2fbbeb1d82667c2b21d78216d5e712aeb7a2ca280e8c3d28eb1620b143edbd2fac046de9e3ebac610221347e38ba422f9906e294bbc6b3e26320663f734b34a931b11ee3b18d9be2bfe99c70cfcd826509ea87d9e10edb70be548e9764387959865ff468e1b3cf06f4f2ab53afada2df3cf573f8b7c2c4c79785d2dfcb9d0e53f8997f236477a573f93cf4a8db0031a424218ba099f2eda18135881cd5470db3210846da86e3a70ef783f6df7b49ee09b0e4d9eab320b0fbeaf4b5b4a2ce5f41917ad4d74bd12387a048ebbb3c55da6c1940e64335f4b248b81800737c74941615e9e4c49021583a39e3902d9ad27bb960f35475074514f9e06320c04b3429f7c82ed95d17788ef7f9a696f59b01ff7310639ca04cacfd9f92fa7e39e94e92a7bab762160ee84b1e25f16ed9c44235fc6640cc5b15d9e0e6aaf9e898c8eec297f6cb68a4eae20a6febfc8917f785839790b" },
	{ "random 1024-bit even modulus, 1024-bit exponent", "d7d8af080df340ad3e3d21095151fa5fdae0927716c55f3605ea5e1ecdb7fc8ab8b588cb263a6512a2d334d4a4e98c2f745d405017f063f88cf6ed9643f13ba440b3e7d84850a48a3b14f36f4da7378ad0a62fdeb6b0cbc42df8b0f3343a8507a2f550e161dcdef60e8ec815c4a36ed30c4ac517e463439e22f8f84a49b2af86", "a7c118732477cda12e675009a74b1f73d688d23d5d0de1df5c0239dd6a0f7b954ffc36431c2b82eed09120b680700a81446c5e19f3fbcb32b11280faf485c5ec358570b91a049a87f564aa36e2f280a8b24032333cdb98bdccc39aa9226ac973a82e6cdf44f3876147d447efd2e70d43a15ff27a57f6df470945a2592e0b9bca", "f661b490c4578c9b68cf376011c06909c4cd7302b21b84344baba040cc4f23b6fe33b207d0c3202a91b149afb43e31fac1594547a35bb871c3f189751fa3ae26e6973fd192b2e0e897ea9e30225f8ee410187f8225bb09a32f5ed492884af71d80d8894f06d5fb31eb0228f975ab4ffef52870a60e7bbed066c66f338d52274c", "82961a8fa0c32bd4aa4c6cede8e936db9427b6b86b9b16685e161c010ec7cf21ff088be753dc7f278f159bfda325c369c801f55ebd120a36c28aa6942f6cdbfc53b7ee95cdfeee5fae6ce04ebd9a3c790402b60ea42308c2eb5539122a9cdec8b92f86b536ca108aedd5c1a4f6452a6ad71ec30ca9aebe26c7b11c71b70c2ca0" },
	{ "random 2048-bit even modulus, 256-bit exponent", "1ab74608dd38eeedd316f53ff7113cb8b0479a43ffe7de06aa5113ab721727e8b716450ecf61b93d67087916749f8c67dd1ba174388fb4a42d6465b33e6a1c8913ed498505f492041484dc2077e73066d315b0ebe64d6eed318f48d15939ca8ab359a44144e4b9d83b4713fb32726827855a43879fafc633ea86d363166826a57d3e2d665862689272a576364c2f4f69713396afccbe4c4b065407deac5400a27914c48e67fb9aa1b0439ec00d5b1209cbbf6dbd90390ab2c2fdede4d7b5936fc880b2f7c49918dbd175a1c4314329cfa8ab7dddbf815795d32a58652867037ec23b0e0d244d29318d65e4828ba29ea05490cfc13978d270fc8e21b1ade2bd9b", "93743166f54f1c6c9d4f5c150fe97a80ebc33367bb28652c399b358c6b388436", "fcb36998015d15d5bc36839d243a7c308a5114297bcb8cf37890e5f5a4af01ce1f1e39143629f6746f1ad8b802db0c74c71865da828eafc6b500f1d45cd8b43fea442517abf23a2485dde29dd6656d954e098d11c1be0d34bddfc6c727b099d578d99652158d46a47b85890fa2d83f278c506f1f3b754fa04305d6731a0b6ebf02d0bdcae44da7aa95ec27cd825329182bdbef3785d41c9d164a6138151a946f97dd4e3e92914acfd2b2bf265863bb36abef045223bf1be0ef729d93e0fcce068701d1c77fe448229dcaddde6d411f8ee2e1a4f69ce4c7f787426da63a5ec2dffd948cad81a036b745436164c9779d86dcaf7d426d11a904b5cd78b4c0f59e62", "98c21496769707228dc2bb2e687b20273c002a2efc8e68cd732dee3e9e57f3191183839d125d2349c59054461552de65eaa793f9ea5cc30311a747c8ddd34262e447cc8e2ec29994163d0ac33a3e7135154aa6cf100e47c2769f8a92d179288399613afe430008f768dfabd25b756ccf482ec8b5cd2d76ae0eaa5ad86adea37fcfd0ffbf1ed7f533996e24ecc3471cd6be60cef839b1001cc16f6c095926ea48f385f65581854dffec74772ce6678a1ae1760aeca39847ec80a4a8ae10447d55ad6ad21773f2d86aeebd548c2566ed9c8f27fc91f54d2a68b6caa1894221ab201c96de8ffd512e03502e4ba688eefc9c9a743dfbe1dc4932922c483257b23af3" },
	{ "random 3072-bit even modulus, 64-bit exponent", "09546e45ed3be5cdb2fa803a1ecbe4d2598f7c2bc8a451e9abe676fc4eb7e7fcadc2f55b47f33fb2a9e4c057315a2b7141c0af8a909c489fa19301b9b60268702ed499ec0e29d6a038ed3c0742fa1d90f1a98852fc63a48a10e038cb37cad88954cc77d1d71398e7a3a7a7733cca59b9f4d7e42f2e8aed6ca25b13cd818eed27bf0e9c6b313fd87ae40f42ef0e123f51b963b6a5b40400748944a4592ab3dc881a93002571294e461c2f0928aa958a31ec7e66326d153cfd3adaa4ee", "adc821998aaeccd4", "afb0f339c2f740244d7e223f10dd17062e9978f03989c79c6082b95baf402ca09b8b65a50ce8cbb073a45240585ff082fe3731454d536631c3898d9432a2a156b0389b683212dd36e16f368fc1f14868a74cd7ad350480096e4a1f36c4afc4e7a589b4b12eb793fe43047b1774b194b0c02ea029bb4ee7db2b342a0e44663df0ceeabe6a71aa09067a27959d99f39e74f827f33c902c6712cefb41a9c0d8720bf62503f620bcad985faa5b4890549248fd6e3e203e6da446a195e92ea9db6d775bac526c39de767d225e4daf71b51688bc15812b9b799a9815a0ed307ac7d9a731209b733336b6ebdc97a9c022031e95d9daa5d628fcd2e0d802941bbb5203f620e15993f37ba2817c9d44a407833b5e5e0138ce7b7e9fca302a77a362953912f97e4a47544943c47d222780fa6030d5a7524648654bdda4432799068098bac8510800e33dc4607a1cdf967c8be0cefec41e03704b257b5bbaf78c66ae3faecd40731fc5acedeec96ee87c7d8a0a77d582c702dc217face48c4a49b373e6657e", "6b2a6f0b95d104e4c2d82546002098bf95515455c6d12d0cfdfc3c2945f9d031c4688f8d8e9717aedce5a5d5b97b21628aa980507cfb512daed585573ed014fc4e73b3070d51277e47754c9f2e2bc8cec74ee89f830da523fa5dcc4622405a1f6c2788fe007ffaf63bd81acf094ece0385f55b5290da8188c395ea1d34c8479c6eff27b7c9dee26395dae62197de4a36142db38f81d33264e7f36259a25369c853ac9637a2b0726254a35a9fd53cb2545833ee7f20b8120889177aba3bc9d45bb8c99a31cf87717bdc6ec3a2782c7f723219b6e409863e8882d3e6c725802fe9252208c60597841d0ac9c5bc6a1a361cc816a6014412977876def042716a7f120931a219af5ff02f279601fa924968024df15368b068268ec121ce1d4d8cb5dc16ac824d4d9a29bf43fa22ccaf4ffc7070508cce51d60c285770c1f0e1c9ca2572a031486c12845f422dfaa59a50003604c941cec2cd371ba7d82e4a49b54073bd70d53ab6cb92e795aa43e2c2a977087729421352fe9dcf09bdeb89359a9494" },
	{ "2^x mod the RFC 3526 group 5 prime", "02", "1c54a0f07ce3a772680975f695e5ea5a32e910631c70fff909c3c068f07e421f772af1ab4f8ebaf3b9fd2b2797b19a1b4cb7a3a7ed46890652e5628753f84ef1d6976d8a7831349bb39e78bbfd40cbd39678f260ee8bf8d76b934489f5bc927265adebbd4b77c1716ee2f0e3959e550a86ce1aca594bda09e6c5ec9307c25ce18220c6decaeb3b5844185f86a9011a71cda70bc408bdd33fdb42a6844469ab7529585bf5080672424bcb7d32aaa375802b52dd967b7999769a705a4cfe8c4b05", "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", "105934fe65121cf8d6778ecbac559c0f20ec92bda305f6aeeb59207d9d7a12b5a4852e69fcfb3eaaacc6273b195d822d1fadea205ff996419450c19c6aef51bb63bbfc1b238983e12b230f04e3d874ce10ca23771862a75266ca665fd9c3dc67cdf4876c246245f4d1065e42e6e38be8795f3785052bc0c4f0293f3fe3f6de2463ae92c36d48356bbaed21602c4e6dbf50cd6395675ca5e274ff70c033c81fd8bdf26ff9b1a89219a3757b9d5da0be54fbcdda61a57fc340e62fd4824d34c4f8" },
};

static void *z_alloc(void *ctx, size_t size) { (void)ctx; return malloc(size); }
static void *z_realloc(void *ctx, size_t old, void *p, size_t size) { (void)ctx; (void)old; return realloc(p, size); }
static void z_free(void *ctx, size_t size, void *p) { (void)ctx; (void)size; free(p); }
static struct ccz_class zclass = { NULL, z_alloc, z_realloc, z_free };

static void z_from_hex(ccz *z, const char *hex)
{
	uint8_t buf[1024];
	size_t n = from_hex(hex, buf);
	ccz_init(&zclass, z);
	ccz_read_uint(z, n, buf);
}

static void test_ccz_expmod(void)
{
	for (size_t i = 0; i < sizeof(modexp) / sizeof(modexp[0]); i++) {
		ccz b, e, m, r;
		z_from_hex(&b, modexp[i].base);
		z_from_hex(&e, modexp[i].exponent);
		z_from_hex(&m, modexp[i].modulus);
		ccz_init(&zclass, &r);
		ccz_expmod(&r, &b, &e, &m);

		uint8_t expected[1024], actual[1024];
		size_t en = from_hex(modexp[i].result, expected);
		size_t an = ccz_write_uint_size(&r);
		ccz_write_uint(&r, an, actual);
		CHECK(same_integer(expected, en, actual, an), modexp[i].name);
		CHECK(ccz_cmp(&r, &m) < 0 || ccz_is_zero(&m), modexp[i].name);

		/* into an operand */
		ccz_expmod(&e, &b, &e, &m);
		an = ccz_write_uint_size(&e);
		ccz_write_uint(&e, an, actual);
		CHECK(same_integer(expected, en, actual, an), modexp[i].name);

		ccz_free(&b); ccz_free(&e); ccz_free(&m); ccz_free(&r);
	}

	/* a few ccz basics used around CCBigNum */
	ccz a, b, r;
	ccz_init(&zclass, &a);
	ccz_init(&zclass, &b);
	ccz_init(&zclass, &r);
	CHECK(ccz_read_radix(&a, 32, "123456789abcdef0123456789ABCDEF0", 16) == 0, "hex");
	CHECK(ccz_write_radix_size(&a, 16) == 32, "hex size");
	char text[64] = { 0 };
	ccz_write_radix(&a, 32, text, 16);
	CHECK(strcmp(text, "123456789ABCDEF0123456789ABCDEF0") == 0, "hex text");
	CHECK(ccz_read_radix(&b, 20, "18446744073709551616", 10) == 0, "decimal");
	CHECK(ccz_bitlen(&b) == 65 && ccz_trailing_zeros(&b) == 64, "2^64");
	ccz_mul(&r, &b, &b);
	CHECK(ccz_bitlen(&r) == 129, "2^128");
	ccz_divmod(&r, &a, &r, &b);
	CHECK(ccz_bitlen(&r) == 65 && ccz_is_zero(&a), "2^128 / 2^64");
	ccz_seti(&a, 1000);
	ccz_subi(&a, &a, 1001);
	CHECK(ccz_is_negative(&a) && ccz_cmpi(&b, 5) > 0 && ccz_cmp(&a, &b) < 0, "signs");
	CHECK(ccz_read_radix(&a, 3, "12g", 16) == CCZ_INVALID_INPUT_ERROR, "bad digit");
	CHECK(ccz_read_radix(&a, 1, "1", 37) == CCZ_INVALID_RADIX_ERROR, "bad radix");
	ccz_free(&a); ccz_free(&b); ccz_free(&r);
}

static void test_pkcs7(void)
{
	static const uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	uint8_t iv0[16], plain[64], cipher[96], back[96];
	for (int i = 0; i < 16; i++)
		iv0[i] = (uint8_t)i;
	from_hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
	         "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", plain);
	uint8_t expected[80];
	/* SP 800-38A F.2.1, then the padding block (pyca/cryptography) */
	from_hex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
	         "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
	         "8cb82807230e1321d3fae00d18cc2012", expected);

	const struct ccmode_cbc *enc = ccaes_cbc_encrypt_mode(), *dec = ccaes_cbc_decrypt_mode();
	const struct ccmode_ecb *eenc = ccaes_ecb_encrypt_mode(), *edec = ccaes_ecb_decrypt_mode();
	cccbc_ctx_decl(enc->size, ectx);
	cccbc_ctx_decl(dec->size, dctx);
	ccecb_ctx_decl(eenc->size, eectx);
	ccecb_ctx_decl(edec->size, edctx);
	cccbc_init(enc, ectx, 16, key);
	cccbc_init(dec, dctx, 16, key);
	ccecb_init(eenc, eectx, 16, key);
	ccecb_init(edec, edctx, 16, key);

	cccbc_iv_decl(16, iv);
	cccbc_set_iv(enc, iv, iv0);
	CHECK(ccpad_pkcs7_encrypt(enc, ectx, iv, 64, plain, cipher) == 80, "SP 800-38A length");
	CHECK(memcmp(cipher, expected, 80) == 0, "SP 800-38A F.2.1 + padding");

	for (size_t len = 0; len <= 33; len++) {
		size_t padded = (len / 16 + 1) * 16;
		cccbc_set_iv(enc, iv, iv0);
		CHECK(ccpad_pkcs7_encrypt(enc, ectx, iv, len, plain, cipher) == padded, "cbc length");
		/* the raw decryption shows the padding RFC 5652 6.3 asks for */
		cccbc_set_iv(dec, iv, iv0);
		cccbc_update(dec, dctx, iv, padded / 16, cipher, back);
		int good = memcmp(back, plain, len) == 0;
		for (size_t i = len; i < padded; i++)
			good &= back[i] == padded - len;
		CHECK(good, "cbc padding bytes");
		cccbc_set_iv(dec, iv, iv0);
		memset(back, 0, sizeof(back));
		CHECK(ccpad_pkcs7_decrypt(dec, dctx, iv, padded, cipher, back) == len && memcmp(back, plain, len) == 0, "cbc round trip");

		CHECK(ccpad_pkcs7_ecb_encrypt(eenc, eectx, len, plain, cipher) == padded, "ecb length");
		ccecb_update(edec, edctx, padded / 16, cipher, back);
		good = memcmp(back, plain, len) == 0;
		for (size_t i = len; i < padded; i++)
			good &= back[i] == padded - len;
		CHECK(good, "ecb padding bytes");
		memset(back, 0, sizeof(back));
		CHECK(ccpad_pkcs7_ecb_decrypt(edec, edctx, padded, cipher, back) == len && memcmp(back, plain, len) == 0, "ecb round trip");
	}

	/* QUIRK (src/ccpad.c): only the last byte is used; observed on macOS 10.14.4 and 26.7.3 */
	uint8_t block[16];
	struct { uint8_t last2[3]; size_t expected; } cases[] = {
		{ { 0, 0, 0 }, 0 }, { { 0, 0, 1 }, 1 }, { { 0, 1, 2 }, 2 }, { { 4, 3, 3 }, 3 },
		{ { 0, 0, 16 }, 16 }, { { 0, 0, 17 }, 0 }, { { 0, 0, 255 }, 0 },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memset(block, 0, sizeof(block));
		memcpy(block + 13, cases[i].last2, 3);
		CHECK(ccpad_pkcs7_decode(16, block) == cases[i].expected, "decode");
	}
	memset(block, 16, sizeof(block));
	block[0] = 15;
	CHECK(ccpad_pkcs7_decode(16, block) == 16, "decode 16 with one 15");
	memset(block, 8, 8);
	CHECK(ccpad_pkcs7_decode(8, block) == 8, "decode 8-byte block");
	block[7] = 9;
	CHECK(ccpad_pkcs7_decode(8, block) == 0, "decode 9 in an 8-byte block");

	/* contract violations: no whole blocks to decrypt */
	CHECK(ccpad_pkcs7_decrypt(dec, dctx, iv, 15, cipher, back) == 0, "15 bytes");
	CHECK(ccpad_pkcs7_decrypt(dec, dctx, iv, 0, cipher, back) == 0, "0 bytes");
}

int main(void)
{
	test_rfc5114();
	test_modp_group("RFC 2409 group 2", ccdh_gp_rfc2409group02(), rfc2409_group2);
	test_modp_group("RFC 3526 group 5", ccdh_gp_rfc3526group05(), rfc3526_group5);
	test_modp_group("RFC 3526 group 14", ccdh_gp_rfc3526group14(), rfc3526_group14);
	CHECK(ccdh_gp_prime(ccdh_gp_rfc3526group05()) == ccdh_gp_prime(ccdh_gp_rfc3526group05()), "same group object");
	CHECK(ccdh_gp_n(ccdh_gp_rfc3526group18()) == ccn_nof(8192), "group 18 size");
	test_ccz_expmod();
	test_pkcs7();
	printf("%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
	return failures != 0;
}
