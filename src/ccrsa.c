#include <corecrypto/ccrsa.h>
#include <stdio.h>
#include <stdlib.h>

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
 * Verify correctness of signature given. Digest is the data being signed.
 *
 * The return value is > 0 if there is an other error.
 * valid is set to false if there is an invalid signature.
 */
int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t *oid,
                          size_t digest_len, const uint8_t *digest,
                          size_t sig_len, const uint8_t *sig,
                          bool *valid)
{
	*valid = 0;
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif

	printf("oid: %d\n", *oid);

	printf("lengths: digest: %zu, signature: %zu\n", digest_len, sig_len);

	cc_size mod_size = ccrsa_ctx_n(key);
	//cc_unit *modulus = *((cc_unit **)key.pub->b);
	cc_unit *modulus = ccrsa_ctx_m(key);
	cc_unit *exponent = ccrsa_ctx_e(key);
	//cc_unit *exponent = *((cc_unit **)(key.pub->b+1));


	// Maybe this should be determined dynamically

	// Length of signature should equal length of modulus
	// mod size: 140198424041744
	printf("mod size: %zu\n", mod_size);
	if (sig_len != ccn_bitlen(mod_size, modulus))
	{
#if DEBUG
		printf("not equal: siglen: %zu, modlen: %zu\n", sig_len, ccn_bitlen(mod_size, modulus));
#endif
		return 1;
	}


	// Compute big uint representation of signature
	cc_size sig_units = ccn_nof_size(sig_len);
	cc_size sig_bytes = ccn_sizeof_n(sig_units);

	cc_unit *s = malloc(sig_bytes);
	if (ccn_read_uint(sig_units, s, sig_len, sig))
	{
#if DEBUG
		printf("%s: failed to read signature\n", __PRETTY_FUNCTION__);
#endif
		return 1;
	}


	// Verify that s is in the range of 0 and modulus-1
	cc_size sig_bits = ccn_bitsof_size(sig_bytes);
	if (ccn_cmp(sig_bits, s, modulus) >= 0 || ccn_bitlen(sig_units, s) == 0)
	{
#if DEBUG
		printf("%s: s not in range of [0, modulus)\n", __PRETTY_FUNCTION__);
#endif
		return 1;
	}

	cc_size m_size = ccn_sizeof_size(digest_len);
	cc_unit *m = malloc(m_size);
	ccn_read_uint(m_size, m, digest_len, digest);

	// m = s^e mod n
	

	struct cczp *zp = malloc(cczp_size(m_size));
	CCZP_N(zp) = ccn_nof_size(digest_len);
	// maybe we should copy modulus into cczp_prime
	cc_unit *zp_mod = (void *)zp + sizeof(struct cczp) /*+ ccn_sizeof_n(1)*/;
	memcpy(zp_mod, modulus, ccn_sizeof_n(CCZP_N(zp)));
	cc_unit *ccn = ((cczp_t)zp).prime->ccn;
	ccn = zp_mod;
	cczp_init(zp);
	//void cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *m, const cc_unit *e);
	
	cc_unit *r = malloc(sig_bytes);
	cczp_power(zp, r, m, exponent);

	printf("we get here \n");

	free(s);
	free(zp);
	free(m);


}

/*
 * Take modulus and exponent and put them next to each other in the public key
 */
void ccrsa_init_pub(ccrsa_pub_ctx_t key, const cc_unit *modulus,
                    const cc_unit *e)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
	//printf("modulus: %u, e: %u\n", *modulus, *e);
#endif
	cc_size mod_size = ccrsa_ctx_n(key);
	memcpy(ccrsa_ctx_m(key), modulus, ccn_sizeof_n(ccrsa_ctx_n(key)));
	memcpy(ccrsa_ctx_e(key), e, ccn_sizeof_n(ccrsa_ctx_n(key)));
	//ccrsa_ctx_m(key) = modulus;
	//ccrsa_ctx_e(key) = e;
	//cc_unit *mod_uint = calloc(mod_size, sizeof(cc_unit));
	//cc_unit *exp_uint = calloc(mod_size, sizeof(cc_unit));
	//cc_unit **modulusDest = (cc_unit **)key.pub->b;
	//cc_unit **exponentDest = modulusDest+1;
	//*modulusDest = mod_uint;
	//*exponentDest = exp_uint;
	/*if (ccn_read_uint(mod_size, mod_uint, mod_size*sizeof(cc_unit), (uint8_t *)modulus))
	{
		return 1;
	}
	if (ccn_read_uint(mod_size, exp_uint, mod_size*sizeof(cc_unit), (uint8_t *)e))
	{
		return 1;
	}*/

#if DEBUG
	/*printf("each byte of key: ");
	for (int i = 0; i < 16; i++)
	{
		printf(" %d", key.pub->b[i]);
	}
	printf("\n");*/
#endif
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
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_get_fullkey_components(const ccrsa_full_ctx_t key, uint8_t *modulus, size_t *modulusLength, uint8_t *exponent, size_t *exponentLength,
                                 uint8_t *p, size_t *pLength, uint8_t *q, size_t *qLength)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccrsa_sign_pkcs1v15(ccrsa_full_ctx_t key, const uint8_t *oid,
                        size_t digest_len, const uint8_t *digest,
                        size_t *sig_len, uint8_t *sig)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
