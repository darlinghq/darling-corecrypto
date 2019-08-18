#include <corecrypto/cczp.h>
#include <stdio.h>

void cczp_init(cczp_t zp)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
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
