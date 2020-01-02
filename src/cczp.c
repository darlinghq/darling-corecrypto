#include <corecrypto/cczp.h>
#include <stdio.h>

void cczp_init(cczp_t zp)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif
	cc_unit *recip = CCZP_RECIP(zp);
	memset(recip, 0, ccn_sizeof_n(CCZP_N(zp)));
	zp.zp->mod_prime = &cczp_mod;
}

void cczp_mod(cczp_const_t zp, cc_unit *r, const cc_unit *s2n, cc_ws_t ws)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *m,
                const cc_unit *e)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
