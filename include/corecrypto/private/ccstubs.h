#ifndef CC_PRIVATE_CCSTUBS_H
#define CC_PRIVATE_CCSTUBS_H

#include <stdio.h>
#include <corecrypto/cc_error.h>

#define CC_STUB(return_value) \
	printf("DARLING CORECRYPTO STUB: %s\n", __FUNCTION__); \
	return return_value;

#define CC_STUB_VOID() CC_STUB(;)

#define CC_STUB_ERR() CC_STUB(CCERR_INTERNAL)

#endif // CC_PRIVATE_CCSTUBS_H
