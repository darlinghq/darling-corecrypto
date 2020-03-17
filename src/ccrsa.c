#include <corecrypto/ccrsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <corecrypto/ccrsa_priv.h>
#include <corecrypto/cc_debug.h>

// Reference used is https://tools.ietf.org/html/rfc8017

int ccrsa_import_pub(ccrsa_pub_ctx_t key, size_t inlen, const uint8_t *der)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_size ccder_decode_rsa_pub_n(const uint8_t *der, const uint8_t *der_end)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_pub_crypt(ccrsa_pub_ctx_t key, cc_unit *out, const cc_unit *in)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_generate_key(unsigned long nbits, ccrsa_full_ctx_t rsa_ctx,
                       size_t e_size, const void *e, struct ccrng_state *rng)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_priv_crypt(ccrsa_priv_ctx_t key, cc_unit *out, const cc_unit *in)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_size ccder_decode_rsa_priv_n(const uint8_t *der, const uint8_t *der_end)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, const uint8_t *der_end)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

/*
 * Verify correctness of signature given. Digest is the digest of the data being signed.
 *
 * The return value is > 0 if there is an other error.
 * valid is set to false if there is an invalid signature.
 */
int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t* oid, size_t digest_len, const uint8_t* digest, size_t sig_len, const uint8_t* sig, bool* valid) {
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);

	cc_println("key", ccrsa_pub_ctx_size(ccn_sizeof_n(ccrsa_ctx_n(key))), (const uint8_t*)ccrsa_ctx_zm(key).u);
	cc_println("oid", strlen((const char*)oid), oid);
	printf("digest_len: %zu\n", digest_len);
	cc_println("digest", digest_len, digest);
	printf("sig_len: %zu\n", sig_len);
	cc_println("sig", sig_len, sig);
#endif

	*valid = false;

	*valid = false;

	cc_unit* s = NULL;
	struct cczp* zp = NULL;
	cc_unit* m = NULL;
	uint8_t* em = NULL;
	uint8_t* em_prime = NULL;

	cc_size mod_size = ccrsa_ctx_n(key);
	cc_unit* modulus = ccrsa_ctx_m(key);
	cc_unit* exponent = ccrsa_ctx_e(key);

	// mod_size is how many units are allocated for the modulus
	// mod_len is how many bytes (*bytes*, not units) are in use
	cc_size mod_bits = ccn_bitlen(mod_size, modulus);
	cc_size mod_len = (mod_bits + 7) / 8;
	mod_size = ccn_nof(mod_bits);

	cc_size sig_bits = ccn_bitsof_size(sig_len);

#if DEBUG
	printf("n of mod: %zu\n", mod_size);
	printf("mod_len: %zu\n", mod_len);
	cc_println("mod", ccn_sizeof_n(mod_size), (const uint8_t*)modulus);
	cc_println("e", ccn_sizeof_n(mod_size), (const uint8_t*)exponent);
#endif

	// number of bits in signature should equal the number of bits in modulus
	if (sig_bits != mod_bits) {
#if DEBUG
		printf("%s: sig_bits (%zu) != mod_bits (%zu)\n", __PRETTY_FUNCTION__, sig_bits, mod_bits);
#endif
		goto fail;
	}

	// Compute big uint representation of signature
	cc_size sig_units = ccn_nof_size(sig_len);
	cc_size sig_bytes = ccn_sizeof_n(sig_units);

	s = __builtin_alloca(sig_bytes);
	memset(s, 0, sig_bytes);
	if (ccn_read_uint(sig_units, s, sig_len, sig)) {
#if DEBUG
		printf("%s: failed to read signature\n", __PRETTY_FUNCTION__);
#endif
		goto fail;
	}

	// Verify that s is in the range of `0` and `modulus - 1`
	if (ccn_cmp(sig_units, s, modulus) >= 0 || ccn_bitlen(sig_units, s) == 0) {
#if DEBUG
		printf("%s: s not in range of [0, modulus)\n", __PRETTY_FUNCTION__);
#endif
		goto fail;
	}

	// copy the modulus into it's own zp structure
	zp = __builtin_alloca(cczp_size(sig_bytes));
	CCZP_N(zp) = sig_units;
	cczp_init(zp);
	memcpy(CCZP_PRIME(zp), modulus, ccn_sizeof_n(CCZP_N(zp)));

	m = __builtin_alloca(sig_bytes);
	// m = s^e mod n
	cczp_power(zp, m, s, exponent);

	// convert `m` into an octet stream in `em`
	em = __builtin_alloca(sig_bytes);
	memset(em, 0, sig_bytes);
	ccn_write_uint(sig_units, m, sig_bytes, em);

#if DEBUG
	cc_println("m", sig_bytes, (const uint8_t*)m);
	cc_println("em", sig_bytes, (const uint8_t*)em);
#endif

	// encode the digest into an EMSA-PKCS#1 v1.5 encoded message
	// to compare with `em`
	em_prime = __builtin_alloca(sig_bytes);
	memset(em_prime, 0, sig_bytes);
	if (ccrsa_emsa_pkcs1v15_encode(sig_bytes, em_prime, digest_len, digest, oid)) {
#if DEBUG
		printf("%s: failed to encode with EMSA-PKCS#1 v1.5\n", __PRETTY_FUNCTION__);
#endif
		goto fail;
	}

#if DEBUG
	cc_println("em_prime", sig_bytes, em_prime);
#endif

	*valid = !memcmp(em, em_prime, sig_bytes);
	if (!*valid) {
#if DEBUG
		printf("%s: em != em_prime\n", __PRETTY_FUNCTION__);
#endif
	}

	return 0;

fail:
#if DEBUG
	printf("%s: failed\n", __PRETTY_FUNCTION__);
#endif
	return 1;
}

/*
 * Take modulus and exponent and put them next to each other in the public key
 */
void ccrsa_init_pub(ccrsa_pub_ctx_t key, const cc_unit *modulus,
                    const cc_unit *e)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif
	cc_size mod_size = ccrsa_ctx_n(key);
	memcpy(ccrsa_ctx_m(key), modulus, ccn_sizeof_n(ccrsa_ctx_n(key)));
	memcpy(ccrsa_ctx_e(key), e, ccn_sizeof_n(ccrsa_ctx_n(key)));
}

int
ccrsa_generate_fips186_key(unsigned long nbits, ccrsa_full_ctx_t fk,
                           size_t e_size, const void *eBytes,
                           struct ccrng_state *rng1, struct ccrng_state *rng2)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_export_pub(const ccrsa_pub_ctx_t key, size_t out_len, uint8_t *out)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_size ccder_decode_rsa_pub_x509_n(const uint8_t *der, const uint8_t *der_end)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_encode_rsa_priv_size(const ccrsa_full_ctx_t key)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, uint8_t *der_end)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_encode_rsa_pub_size(const ccrsa_pub_ctx_t key)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int
ccrsa_make_fips186_key(unsigned long nbits,
                       const cc_size e_n, const cc_unit *e,
                       const cc_size xp1Len, const cc_unit *xp1, const cc_size xp2Len, const cc_unit *xp2,
                       const cc_size xpLen, const cc_unit *xp,
                       const cc_size xq1Len, const cc_unit *xq1, const cc_size xq2Len, const cc_unit *xq2,
                       const cc_size xqLen, const cc_unit *xq,
                       ccrsa_full_ctx_t fk,
                       cc_size *np, cc_unit *r_p,
                       cc_size *nq, cc_unit *r_q,
                       cc_size *nm, cc_unit *r_m,
                       cc_size *nd, cc_unit *r_d)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_get_pubkey_components(const ccrsa_pub_ctx_t pubkey, uint8_t *modulus, size_t *modulusLength, uint8_t *exponent, size_t *exponentLength)
{
	*modulusLength = *exponentLength = ccn_sizeof_n(ccrsa_ctx_n(pubkey));
	memcpy(modulus, ccrsa_ctx_m(pubkey), *modulusLength);
	memcpy(exponent, ccrsa_ctx_e(pubkey), *exponentLength);
	return 0;
}

int ccrsa_get_fullkey_components(const ccrsa_full_ctx_t key, uint8_t *modulus, size_t *modulusLength, uint8_t *exponent, size_t *exponentLength,
                                 uint8_t *p, size_t *pLength, uint8_t *q, size_t *qLength)
{
	ccrsa_pub_ctx_t pub = ccrsa_ctx_public(key);
	ccrsa_priv_ctx_t priv = ccrsa_ctx_private(key);
	*modulusLength = *exponentLength = ccn_sizeof_n(ccrsa_ctx_n(pub));
	*pLength = *qLength = ccn_sizeof_n(priv.zp.zp->n);
	memcpy(modulus, ccrsa_ctx_m(pub), *modulusLength);
	memcpy(exponent, ccrsa_ctx_e(pub), *exponentLength);
	memcpy(p, ccrsa_ctx_private_zp(priv).prime->ccn, *pLength);
	memcpy(q, ccrsa_ctx_private_zq(priv).prime->ccn, *qLength);
	return 0;
}

int ccrsa_sign_pkcs1v15(ccrsa_full_ctx_t key, const uint8_t *oid,
                        size_t digest_len, const uint8_t *digest,
                        size_t *sig_len, uint8_t *sig)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
