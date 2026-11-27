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
 * Finite field Diffie-Hellman (PKCS #3, RFC 2631, NIST SP 800-56A).
 *
 * Group layout (ccdh.h): the cczp header and prime, the reciprocal (n + 1
 * units), then g, q and l. q is zero when the group's subgroup order is not
 * known, l is the private value length in bits, or zero.
 * A full key holds y (n units) followed by the private value x (n units).
 */

#include <corecrypto/ccdh.h>
#include <corecrypto/cc.h>
#include <corecrypto/private/dbn.h>
#include <stdio.h>
#include <string.h>

/* tries before key generation gives up; each try fails with probability < 1/2 */
#define DH_KEYGEN_TRIES 100

static inline cc_unit *dh_private_value(ccdh_full_ctx_t key)
{
	return ccdh_ctx_y(key) + ccdh_ctx_n(key);
}

static inline const cc_unit *dh_order(ccdh_const_gp_t gp)
{
	return ccdh_gp_g(gp) + ccdh_gp_n(gp);
}

static inline cc_size dh_private_length(ccdh_const_gp_t gp)
{
	return *(const cc_size *)(dh_order(gp) + ccdh_gp_n(gp));
}

/* bit length of a public value (p or q) */
static size_t dh_bit_length(cc_size n, const cc_unit *x)
{
	for (cc_size i = n; i > 0; i--) {
		if (x[i - 1]) {
			size_t bits = (i - 1) * CCN_UNIT_BITS;
			for (cc_unit top = x[i - 1]; top; top >>= 1)
				bits++;
			return bits;
		}
	}
	return 0;
}

static int dh_same_group(ccdh_const_gp_t a, ccdh_const_gp_t b)
{
	if (ccdh_gp_prime(a) == ccdh_gp_prime(b))
		return 1;
	cc_size n = ccdh_gp_n(a);
	if (n != ccdh_gp_n(b))
		return 0;
	return dbn_equal(n, ccdh_gp_prime(a), ccdh_gp_prime(b)) &&
	       dbn_equal(n, ccdh_gp_g(a), ccdh_gp_g(b));
}

/*
 * Public key check of SP 800-56A section 5.6.2.3.1: 2 <= y <= p - 2, and
 * y^q mod p == 1 when the group's order q is known.
 */
static int dh_check_public(ccdh_const_gp_t gp, const cc_unit *y)
{
	const cc_size n = ccdh_gp_n(gp);
	const cc_unit *p = ccdh_gp_prime(gp);
	const cc_unit *q = dh_order(gp);
	cc_unit bound[n], check[n];
	int result = 0;

	/* y >= 2 */
	memset(bound, 0, sizeof(bound));
	bound[0] = 2;
	if (dbn_less(n, y, bound))
		result = CCDH_SAFETY_CHECK;

	/* y <= p - 2, that is y < p - 1 */
	memset(check, 0, sizeof(check));
	check[0] = 1;
	dbn_sub(n, bound, p, check);
	if (!dbn_less(n, y, bound))
		result = CCDH_SAFETY_CHECK;

	if (result == 0 && !dbn_is_zero(n, q)) {
		if (dbn_modexp(n, check, y, n, q, p))
			result = CCDH_ERROR_DEFAULT;
		else {
			memset(bound, 0, sizeof(bound));
			bound[0] = 1;
			if (!dbn_equal(n, check, bound))
				result = CCDH_SAFETY_CHECK;
		}
	}

	return result;
}

/*
 * A private value x for the group, per the first rule that applies:
 * - q known: 1 <= x <= q - 1 (SP 800-56A 5.6.1.1, by testing candidates);
 * - l set and 0 < l < bitlen(p): 2^(l-1) <= x < 2^l (PKCS #3 section 7.1);
 * - otherwise: 1 <= x <= p - 2.
 */
static int dh_pick_private(ccdh_const_gp_t gp, struct ccrng_state *rng, cc_unit *x)
{
	const cc_size n = ccdh_gp_n(gp);
	const cc_unit *p = ccdh_gp_prime(gp);
	const cc_unit *q = dh_order(gp);
	const size_t l = dh_private_length(gp);
	const size_t pbits = dh_bit_length(n, p);
	cc_unit upper[n], one[n];

	memset(one, 0, sizeof(one));
	one[0] = 1;

	if (dbn_is_zero(n, q) && l > 0 && l < pbits) {
		memset(x, 0, ccn_sizeof_n(n));
		if (ccn_random_bits(l, x, rng))
			return CCDH_ERROR_DEFAULT;
		x[(l - 1) / CCN_UNIT_BITS] |= (cc_unit)1 << ((l - 1) % CCN_UNIT_BITS);
		return 0;
	}

	/* candidates must be below upper: q, or p - 1 */
	if (!dbn_is_zero(n, q))
		memcpy(upper, q, sizeof(upper));
	else
		dbn_sub(n, upper, p, one);
	const size_t bits = dh_bit_length(n, upper);
	if (bits < 2)
		return CCDH_INVALID_DOMAIN_PARAMETER;

	for (int tries = 0; tries < DH_KEYGEN_TRIES; tries++) {
		memset(x, 0, ccn_sizeof_n(n));
		if (ccn_random_bits(bits, x, rng))
			return CCDH_ERROR_DEFAULT;
		if (!dbn_is_zero(n, x) && dbn_less(n, x, upper))
			return 0;
	}
	cc_clear(ccn_sizeof_n(n), x);
	return CCDH_GENERATE_KEY_TOO_MANY_TRIES;
}

int ccdh_init_gp(ccdh_gp_t gp, cc_size n, cc_unit *p, cc_unit *g, cc_size l)
{
	if (n == 0 || (p[0] & 1) == 0)
		return CCDH_INVALID_DOMAIN_PARAMETER;

	CCDH_GP_N(gp) = n;
	ccn_set(n, CCDH_GP_PRIME(gp), p);
	if (cczp_init(CCDH_GP_ZP(gp)))
		return CCDH_INVALID_DOMAIN_PARAMETER;
	ccn_set(n, CCDH_GP_G(gp), g);
	memset(CCDH_GP_Q(gp), 0, ccn_sizeof_n(n));
	CCDH_GP_L(gp) = l;

	/* 2 <= g <= p - 2 */
	if (dh_check_public((ccdh_const_gp_t)gp, g))
		return CCDH_INVALID_DOMAIN_PARAMETER;
	return 0;
}

int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng,
                      ccdh_full_ctx_t key)
{
	const cc_size n = ccdh_gp_n(gp);
	int result;

	ccdh_ctx_init(gp, ccdh_ctx_public(key));
	cc_unit *y = ccdh_ctx_y(key);
	cc_unit *x = dh_private_value(key);

	for (int tries = 0; tries < DH_KEYGEN_TRIES; tries++) {
		result = dh_pick_private(gp, rng, x);
		if (result)
			break;
		if (dbn_modexp(n, y, ccdh_gp_g(gp), n, x, ccdh_gp_prime(gp))) {
			result = CCDH_ERROR_DEFAULT;
			break;
		}
		/* only a degenerate generator can land outside [2, p - 2] */
		result = dh_check_public(gp, y);
		if (result == 0)
			return 0;
	}

	cc_clear(ccn_sizeof_n(n), x);
	cc_clear(ccn_sizeof_n(n), y);
	return result ? result : CCDH_GENERATE_KEY_TOO_MANY_TRIES;
}

int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                    ccdh_pub_ctx_t key)
{
	const cc_size n = ccdh_gp_n(gp);

	ccdh_ctx_init(gp, key);
	if (ccn_read_uint(n, ccdh_ctx_y(key), in_len, in))
		return CCDH_INVALID_INPUT;
	return dh_check_public(gp, ccdh_ctx_y(key));
}

void ccdh_export_pub(ccdh_pub_ctx_t key, void *out)
{
	ccn_write_uint(ccdh_ctx_n(key), ccdh_ctx_y(key), ccdh_export_pub_size(key), out);
}

/* z = y_peer^x mod p, with the checks of SP 800-56A 5.7.1.1 */
static int dh_agree(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key, cc_unit *z)
{
	ccdh_const_gp_t gp = ccdh_ctx_gp(private_key);
	const cc_size n = ccdh_gp_n(gp);
	int result;

	if (!dh_same_group(gp, ccdh_ctx_gp(public_key)))
		return CCDH_DOMAIN_PARAMETER_MISMATCH;

	result = dh_check_public(gp, ccdh_ctx_y(public_key));
	if (result)
		return result;

	if (dbn_modexp(n, z, ccdh_ctx_y(public_key), n, dh_private_value(private_key), ccdh_gp_prime(gp)))
		return CCDH_ERROR_DEFAULT;

	/* z == 1 (or 0) means the peer key was not in the group */
	cc_unit one[n];
	memset(one, 0, sizeof(one));
	one[0] = 1;
	if (dbn_is_zero(n, z) | dbn_equal(n, z, one)) {
		cc_clear(ccn_sizeof_n(n), z);
		return CCDH_SAFETY_CHECK;
	}
	return 0;
}

int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key,
                     cc_unit *computed_key)
{
	int result = dh_agree(private_key, public_key, computed_key);
	if (result)
		cc_clear(ccn_sizeof_n(ccdh_ctx_n(private_key)), computed_key);
	return result;
}

/*
 * The shared secret as a big-endian integer without leading zero bytes
 * (CommonCrypto's CCDHComputeKey documents that form). *len is the size of
 * key on input and the length written on output.
 */
int ccdh_compute_shared_secret(ccdh_full_ctx_t ctx, ccdh_pub_ctx_t pub, size_t *len, const void *key, struct ccrng_state *rng)
{
	const cc_size n = ccdh_ctx_n(ctx);
	cc_unit z[n];
	int result;

	(void)rng; /* the exponentiation is constant time; no blinding needed */

	result = dh_agree(ctx, pub, z);
	if (result == 0) {
		size_t size = ccn_write_uint_size(n, z);
		if (size > *len)
			result = CCDH_INVALID_INPUT;
		else {
			ccn_write_uint(n, z, size, (void *)key);
			*len = size;
		}
	}

	cc_clear(sizeof(z), z);
	return result;
}

cc_size ccder_decode_dhparam_n(const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_dhparams(ccdh_gp_t gp, const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

CC_CONST CC_NONNULL_TU((1))
const cc_unit *ccdh_gp_prime(ccdh_const_gp_t gp) {
    return cczp_prime(CCDH_CONST_GP_T_ZP(gp));
}

CC_CONST CC_NONNULL_TU((1))
size_t ccdh_ccn_size(ccdh_const_gp_t gp) {
    return ccn_sizeof_n(cczp_n(CCDH_CONST_GP_T_ZP(gp)));
}

CC_CONST CC_NONNULL_TU((1))
const cc_unit *ccdh_gp_g(ccdh_const_gp_t gp) {
#if CORECRYPTO_USE_TRANSPARENT_UNION
    return CCDH_GP_G(gp._ncgp);
#else
    return CCDH_GP_G((ccdh_gp_t)gp);
#endif
}

CC_CONST CC_NONNULL_TU((1))
cc_size ccdh_gp_n(ccdh_const_gp_t gp) {
    return cczp_n(CCDH_CONST_GP_T_ZP(gp));
}
