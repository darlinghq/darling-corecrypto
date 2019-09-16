#include <stdlib.h>
#include <ctest.h>
#include "../include/corecrypto/cc.h"

enum { SIZE = 256 };

CTEST(cc, cc_zero) {
	unsigned char buffer[SIZE];
	for(size_t i = 0 ; i < SIZE; ++i) {
		buffer[i] = (unsigned char) i;
	}
	cc_zero(SIZE, buffer);
	for (size_t i = 0; i < SIZE; ++i) {
		ASSERT_EQUAL('\0', buffer[i]);
	}
}

CTEST(cc, cc_clear) {
	unsigned char buffer[SIZE];
	for(size_t i = 0 ; i < SIZE; ++i) {
		buffer[i] = (unsigned char) i;
	}
	cc_clear(SIZE, buffer);
	for (size_t i = 0; i < SIZE; ++i) {
		ASSERT_EQUAL('\0', buffer[i]);
	}
}

CTEST(cc, cc_copy) {
	unsigned char buffer1[SIZE];
	unsigned char buffer2[SIZE];

	for(size_t i = 0 ; i < SIZE; ++i) {
		buffer1[i] = (unsigned char) rand();
	}
	cc_copy(SIZE, buffer2, buffer1);
	for (size_t i = 0; i < SIZE; ++i) {
		ASSERT_EQUAL(buffer1[i], buffer2[i]);
	}
}

CTEST(cc, cc_xor) {
	unsigned char buffer1[SIZE];
	unsigned char buffer2[SIZE];
	unsigned char buffer3[SIZE];

	for(size_t i = 0 ; i < SIZE; ++i) {
		buffer1[i] = (unsigned char) rand();
		buffer2[i] = (unsigned char) rand();
	}
	cc_xor(SIZE, buffer3, buffer1, buffer2);
	for (size_t i = 0; i < SIZE; ++i) {
		ASSERT_EQUAL(buffer3[i], buffer1[i] ^ buffer2[i]);
	}
	cc_xor(SIZE, buffer3, buffer3, buffer2);
	for (size_t i = 0; i < SIZE; ++i) {
		ASSERT_EQUAL(buffer3[i], buffer1[i]);
	}
	cc_xor(SIZE, buffer3, buffer3, buffer3);
	for (size_t i = 0; i < SIZE; ++i) {
		ASSERT_EQUAL('\0', buffer3[i]);
	}
}

CTEST(cc, cc_cmp_safe) {
	unsigned char buffer1[SIZE];
	unsigned char buffer2[SIZE];
	for(size_t i = 0 ; i < SIZE; ++i) {
		buffer1[i] = (unsigned char) rand();
		buffer2[i] = (unsigned char) rand();
	}

	ASSERT_EQUAL(0, cc_cmp_safe(SIZE, buffer1, buffer1));
	ASSERT_EQUAL(1,cc_cmp_safe(SIZE, buffer1, buffer2));
	ASSERT_EQUAL(1,cc_cmp_safe(0, buffer1, buffer1));
}

CTEST(cc, CC_SWAP) {
	unsigned  int a = 127;
	unsigned  int b = 257;
	CC_SWAP(a,b);
	ASSERT_EQUAL(a, 257);
	ASSERT_EQUAL(b, 127);
	CC_SWAP(a,b);
	ASSERT_EQUAL(a, 127);
	ASSERT_EQUAL(b, 257);
}

CTEST(cc, CC_MAX) {
	ASSERT_EQUAL(128, CC_MAX(63, 128));
	ASSERT_EQUAL(-128, CC_MAX(-163, -128));
	ASSERT_EQUAL(128, CC_MAX(128, -128));
}

CTEST(cc, CC_MIN) {
	ASSERT_EQUAL(63, CC_MIN(63, 128));
	ASSERT_EQUAL(-163, CC_MIN(-163, -128));
	ASSERT_EQUAL(-128, CC_MIN(128, -128));
}
