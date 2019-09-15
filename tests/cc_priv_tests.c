#include <ctest.h>
#include "../include/corecrypto/cc_priv.h"

CTEST(cc, cc_muxp) {
	const unsigned char a;
	const unsigned char b;
	ASSERT_TRUE(&a == cc_muxp(1, (void *) &a, (void *) &b));
	ASSERT_TRUE(&b == cc_muxp(0, (void *) &a, (void *) &b));
}
