#include <stdlib.h>
#include <stdio.h>
#include <ctest.h>
#include <corecrypto/cczp.h>

#define ASSERT_CCN_UNIT(exp, act, n) ASSERT_DATA((const uint8_t *)exp,\
	ccn_sizeof_n(n),\
	(const uint8_t *)act,\
	ccn_sizeof_n(n))

CTEST(cczp, cczp_mod_prime)
{
#ifdef __LP64__
	// not actually a prime
	cc_unit prime[] = {
		0x478db7765cb54f9,
		0xdcfc21642dee692b,
		0xeb2d680e153fe5e2,
		0x00000eeb8fe1c4b1
	};

	const cc_unit s[] = {
		0xda51d233a8c999b8,
		0x9891c4a141451839,
		0x764b27454661a386,
		0x0000a6dc85bf833a,
		0x0,
		0x0,
		0x0,
		0x0
	};

	const cc_unit expected[] = {
		0x2a270943bd01bb41
		0x446a5cc2eca950f1
		0x74e240c8cede425c
		0xffff680f0a224177
	
	};

#endif
	cc_unit actual[4];

	cczp_t zp;
	zp.u = malloc(cczp_size(4));
	CCZP_N(zp) = 4;
	//cc_unit *zp_prime = CCZP_PRIME(&zp);
	//printf("%p, %p, %ld\n", &zp, &zp_prime, (void*)&zp - (void*)&zp_prime);
	memcpy(CCZP_PRIME(zp), prime, ccn_sizeof_n(4));
	cczp_init(zp);
	CCZP_MOD_PRIME(zp)((const struct cczp *)zp.zp, actual, s, NULL);

	ASSERT_CCN_UNIT(expected, actual, 4);
}
