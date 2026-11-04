/*
 * ccec_generate_key must return a fresh random private key on every call (it once
 * returned one hard-coded scalar whenever DEBUG was defined) and the key must work:
 * an ECDSA signature made with it verifies under its public key, and ECDH between
 * two generated keys agrees in both directions. P-256 and P-384.
 *
 * The signing step is done here with the library's field arithmetic because
 * ccec_sign is a stub; ccec_verify is checked against RFC 6979 in ecdsa_rfc6979.c.
 *
 * Build and run from the repository root (on an aarch64 host add -D__arm64__ so
 * cc_unit is 64-bit). Compile it with and without -DDEBUG; both must pass:
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -w \
 *     -Iinclude $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *     | grep 'src/' | tr -d '\t ' | sort -u) tests/standalone/ecc_generate_key.c \
 *     -o /tmp/ecc_generate_key && /tmp/ecc_generate_key
 */
#include <corecrypto/ccec.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/private/ccec_extra.h>
#include <corecrypto/private/ccec_points.h>
#include <corecrypto/private/ccn_extra.h>
#include <corecrypto/private/cczp_extra.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void fail(const char* curve, const char* what) {
	printf("FAIL %s: %s\n", curve, what);
	failures++;
}

static size_t put_int(uint8_t* out, const uint8_t* x, size_t len) {
	while (len > 1 && x[0] == 0) {
		x++;
		len--;
	}
	size_t pad = (x[0] & 0x80) ? 1 : 0;
	out[0] = 0x02;
	out[1] = (uint8_t)(len + pad);
	if (pad)
		out[2] = 0;
	memcpy(out + 2 + pad, x, len);
	return 2 + pad + len;
}

/* ECDSA sign digest (shorter than the order) with private scalar d and nonce kk. */
static size_t sign(ccec_const_cp_t cp, const cc_unit* d, const cc_unit* kk, const uint8_t* digest, size_t digest_len, uint8_t* der) {
	const cc_size n = ccec_cp_n(cp);
	const size_t nb = ccn_sizeof_n(n);
	const cc_unit* order = ccec_cp_o(cp);

	uint8_t zp_bytes[cczp_size(ccn_sizeof_n(n))];
	memset(zp_bytes, 0, sizeof zp_bytes);
	cczp_t zp = (cczp_t)(struct cczp*)zp_bytes;
	CCZP_N(zp) = n;
	memcpy(CCZP_PRIME(zp), order, ccn_sizeof_n((2 * n) + 1));
	zp.zp->mod_prime = cczp_mod;

	cc_unit e[n], r[n], s[n], kinv[n], t[n];
	memset(e, 0, sizeof e);
	ccn_read_uint(n, e, digest_len, digest);

	cc_unit px[2 * n], py[n], pz[n], tz[n];
	memset(px, 0, sizeof px);
	memset(py, 0, sizeof py);
	memset(pz, 0, sizeof pz);
	memset(tz, 0, sizeof tz);
	tz[0] = 1;
	ccec_projective_point_container_t P = {.n = n, .x = px, .y = py, .z = pz};
	ccec_projective_multiply(cp, P, (ccec_const_projective_point_container_t){.n = n, .x = ccec_cp_x(cp), .y = ccec_cp_y(cp), .z = tz}, n, kk);
	ccec_affine_point_container_from_projective_point(cp, (ccec_affine_point_container_t){.n = n, .x = px, .y = py}, ccec_projective_point_container_constify(P));
	memset(r, 0, sizeof r);
	cczp_mod(zp, r, px, NULL);

	memset(kinv, 0, sizeof kinv);
	if (ccn_modular_multiplicative_inverse(n, kinv, kk, order) != 0)
		return 0;
	cczp_mul_mod(zp, t, r, d); /* r * d */
	if (ccn_add(n, t, t, e) || ccn_cmp(n, t, order) >= 0) /* + e, then reduce once (both terms < order) */
		ccn_sub(n, t, t, order);
	cczp_mul_mod(zp, s, kinv, t);

	uint8_t rb[nb], sb[nb];
	ccn_write_uint_padded(n, r, nb, rb);
	ccn_write_uint_padded(n, s, nb, sb);
	size_t body = put_int(der + 2, rb, nb);
	body += put_int(der + 2 + body, sb, nb);
	der[0] = 0x30;
	der[1] = (uint8_t)body;
	return 2 + body;
}

static void check_curve(const char* name, ccec_const_cp_t cp) {
	int err = 0;
	struct ccrng_state* rng = ccrng(&err);
	const cc_size n = ccec_cp_n(cp);
	const size_t nb = ccn_sizeof_n(n);

	ccec_full_ctx_decl_cp(cp, a);
	ccec_full_ctx_decl_cp(cp, b);
	ccec_full_ctx_decl_cp(cp, c);
	if (ccec_generate_key(cp, rng, a) != 0 || ccec_generate_key(cp, rng, b) != 0 || ccec_generate_key(cp, rng, c) != 0) {
		fail(name, "ccec_generate_key returned an error");
		return;
	}

	if (!memcmp(ccec_ctx_k(a), ccec_ctx_k(b), nb) || !memcmp(ccec_ctx_k(a), ccec_ctx_k(c), nb) || !memcmp(ccec_ctx_k(b), ccec_ctx_k(c), nb))
		fail(name, "two generated private keys are identical");

	cc_unit any = 0;
	for (cc_size i = 0; i < n; i++)
		any |= ccec_ctx_k(a)[i];
	if (any == 0 || ccn_cmp(n, ccec_ctx_k(a), ccec_cp_o(cp)) >= 0)
		fail(name, "private scalar outside [1, order - 1]");

	/* the public key survives an export/import round trip */
	uint8_t pub[1 + 2 * 66];
	size_t pub_len = ccec_export_pub_size(ccec_ctx_pub(a));
	ccec_export_pub(ccec_ctx_pub(a), pub);
	ccec_pub_ctx_decl_cp(cp, apub);
	if (ccec_import_pub(cp, pub_len, pub, apub) != 0)
		fail(name, "public key import");

	/* sign with a's private key (nonce 0x1234567890abcdef), verify under its public key */
	static const uint8_t digest[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
	cc_unit nonce[n];
	memset(nonce, 0, sizeof nonce);
	nonce[0] = 0x1234567890abcdefULL & CCN_UNIT_MASK;
	uint8_t sig[2 + 2 * (2 + 1 + 66)];
	size_t sig_len = sign(cp, ccec_ctx_k(a), nonce, digest, sizeof digest, sig);
	bool valid = false;
	if (sig_len == 0 || ccec_verify(apub, sizeof digest, digest, sig_len, sig, &valid) != 0 || !valid)
		fail(name, "signature made with the generated key does not verify");
	uint8_t other[32];
	memcpy(other, digest, sizeof other);
	other[31] ^= 1;
	valid = true;
	if (ccec_verify(apub, sizeof other, other, sig_len, sig, &valid) != 0 || valid)
		fail(name, "signature verifies for a different digest");

	/* ECDH agrees in both directions */
	uint8_t sab[66], sba[66];
	size_t lab = sizeof sab, lba = sizeof sba;
	if (ccecdh_compute_shared_secret(a, ccec_ctx_pub(b), &lab, sab, rng) != 0 ||
	    ccecdh_compute_shared_secret(b, ccec_ctx_pub(a), &lba, sba, rng) != 0 ||
	    lab != lba || memcmp(sab, sba, lab) != 0)
		fail(name, "ECDH shared secrets differ");
}

/* A generator that fails (after writing 0x01 bytes), or returns zero bytes for the first `zeros` calls and 0x01 bytes afterwards. */
struct scripted_rng {
	struct ccrng_state rng;
	int zeros;
	int fail;
};

static int scripted_generate(struct ccrng_state* rng, size_t len, void* out) {
	struct scripted_rng* s = (struct scripted_rng*)rng;
	/* a failing generator still leaves usable-looking bytes behind, so ignoring its error would yield a key */
	memset(out, s->zeros-- > 0 ? 0 : 0x01, len);
	return s->fail ? -1 : 0;
}

static void check_rng_paths(const char* name, ccec_const_cp_t cp) {
	ccec_full_ctx_decl_cp(cp, key);
	struct scripted_rng s = {.rng = {.generate = scripted_generate}};
	const cc_size n = ccec_cp_n(cp);

	s.fail = 1;
	if (ccec_generate_key(cp, &s.rng, key) == 0)
		fail(name, "an RNG failure was not reported");

	s.fail = 0;
	s.zeros = 1000;
	if (ccec_generate_key(cp, &s.rng, key) == 0)
		fail(name, "an all-zero RNG produced a key");

	s.zeros = 3; /* three zero scalars are redrawn, the fourth draw (all 0x01 bytes) is accepted */
	if (ccec_generate_key(cp, &s.rng, key) != 0)
		fail(name, "a zero scalar was not redrawn");
	cc_unit any = 0;
	for (cc_size i = 0; i < n; i++)
		any |= ccec_ctx_k(key)[i];
	if (any == 0)
		fail(name, "the key has a zero private scalar");
}

static void check_unsupported(const char* name, ccec_const_cp_t cp) {
	int err = 0;
	ccec_full_ctx_decl_cp(cp, key);
	if (ccec_generate_key(cp, ccrng(&err), key) == 0)
		fail(name, "key generation on an unsupported curve returned success");
}

int main(void) {
	alarm(120);
	check_curve("P-256", ccec_cp_256());
	check_curve("P-384", ccec_cp_384());
	check_rng_paths("P-256", ccec_cp_256());
	check_rng_paths("P-384", ccec_cp_384());
	check_unsupported("P-224", ccec_cp_224());
	check_unsupported("P-521", ccec_cp_521());
	printf("%d failure(s)\n", failures);
	return failures != 0;
}
