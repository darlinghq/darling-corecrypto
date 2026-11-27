#include <corecrypto/ccdh_gp.h>
#include <corecrypto/cc.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "ccdh_modp_groups.h"

/*
 * The MODP groups of RFC 2409 section 6.2 and RFC 3526, all with generator 2.
 * Each group is built the first time it is asked for, in static storage laid
 * out as ccdh.h describes (cczp header, prime, reciprocal, g, q, l).
 * q is left zero (the RFCs give no subgroup order) and so is l (no private
 * value length), so ccdh_generate_key picks private values in [1, p - 2].
 */

#define MODP_UNITS(bits) ccn_nof(bits)
#define MODP_STORAGE_UNITS(bits) \
	(ccn_nof_size(ccdh_gp_size(ccn_sizeof_n(MODP_UNITS(bits)))))

static void modp_build(cc_unit *storage, const uint8_t *prime, size_t prime_size)
{
	ccdh_gp_t gp = (ccdh_gp_t)(ccdh_gp *)storage;
	const cc_size n = ccn_nof_size(prime_size);
	cc_unit p[n], g[n];

	ccn_read_uint(n, p, prime_size, prime);
	memset(g, 0, sizeof(g));
	g[0] = 2;
	ccdh_init_gp(gp, n, p, g, 0);
}

#define MODP_GROUP(name, bits) \
	static cc_unit modp_##name##_storage[MODP_STORAGE_UNITS(bits)] __attribute__((aligned(16))); \
	static pthread_once_t modp_##name##_once = PTHREAD_ONCE_INIT; \
	static void modp_##name##_build(void) \
	{ \
		modp_build(modp_##name##_storage, modp_##name##_prime, sizeof(modp_##name##_prime)); \
	} \
	ccdh_const_gp_t ccdh_gp_##name(void) \
	{ \
		pthread_once(&modp_##name##_once, modp_##name##_build); \
		return (ccdh_const_gp_t)(const ccdh_gp *)modp_##name##_storage; \
	}

MODP_GROUP(rfc2409group02, 1024)
MODP_GROUP(rfc3526group05, 1536)
MODP_GROUP(rfc3526group14, 2048)
MODP_GROUP(rfc3526group15, 3072)
MODP_GROUP(rfc3526group16, 4096)
MODP_GROUP(rfc3526group17, 6144)
MODP_GROUP(rfc3526group18, 8192)

ccdh_const_gp_t ccdh_gp_rfc5114_MODP_1024_160() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccdh_gp_rfc5114_MODP_2048_224() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccdh_gp_rfc5114_MODP_2048_256() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccsrp_gp_rfc5054_1024() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccsrp_gp_rfc5054_2048() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccsrp_gp_rfc5054_3072() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccsrp_gp_rfc5054_4096() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

ccdh_const_gp_t ccsrp_gp_rfc5054_8192() {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

