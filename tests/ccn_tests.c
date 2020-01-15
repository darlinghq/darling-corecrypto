#include <stdlib.h>
#include <ctest.h>
#include <corecrypto/ccn.h>

#define ASSERT_CCN_UNIT(exp, act, n) ASSERT_DATA((const uint8_t *)exp,\
	ccn_sizeof_n(n),\
	(const uint8_t *)act,\
	ccn_sizeof_n(n))

CTEST(ccn, ccn_shift_right) {
	const cc_size units = 16;
	const cc_size shift = 24;
	
#ifdef __LP64__
	cc_unit input[] = {
		0x179b057f4285e0f4,
		0x6373d54a49b82048,
		0x574f7cc723891999,
		0x7def9e087e705fcf,
		0x3a24fe3152ac1f2,
		0x2a2301b960462e4b,
		0x1f896f4e77ea7a0e,
		0x42f36aa37ade15ab,
		0xa60cc9259168a90,
		0x56e321a159b4fd97,
		0x7974f2836cddb4c0,
		0x4f85e1165e7c9423,
		0x44e1b64b3e871941,
		0x178b1a792d770a02,
		0x6232209f48fbd916,
		0xe6958c92643fb83
	};

	const cc_unit expected[] = {
		0xb82048179b057f42,
		0x8919996373d54a49,
		0x705fcf574f7cc723,
		0x2ac1f27def9e087e,
		0x462e4b03a24fe315,
		0xea7a0e2a2301b960,
		0xde15ab1f896f4e77,
		0x168a9042f36aa37a,
		0xb4fd970a60cc9259,
		0xddb4c056e321a159,
		0x7c94237974f2836c,
		0x8719414f85e1165e,
		0x770a0244e1b64b3e,
		0xfbd916178b1a792d,
		0x43fb836232209f48,
		0xe6958c926
	};
	cc_unit expected_ret = 0x85e0f40000000000;
#endif

	cc_unit actual_ret = ccn_shift_right(units, input, input, shift);

	ASSERT_EQUAL_U(expected_ret, actual_ret);
	ASSERT_CCN_UNIT(expected, input, units);
}
