/*
 * Copyright (c) 2016 Lubos Dolezel
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

#ifndef _CORECRYPTO_CC_H
#define _CORECRYPTO_CC_H

#include <corecrypto/cc_config.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#define cc_aligned_struct(alignment)  \
    typedef struct\
	{ \
		uint8_t dummy[alignment]; \
    } __attribute__((aligned(alignment)))

#define cc_ctx_n(type, size) ((sizeof(type) + size - 1) / sizeof(type))

#define cc_ctx_sizeof(type, size) sizeof(type[cc_ctx_n(type, size)])

#define cc_ctx_decl(type, size, name) type name[cc_ctx_n(type, size)]

inline void cc_zero(size_t size ,void* data)
{
	memset(data, 0, size);
}

void cc_clear(size_t len, void* dst);

inline void* cc_copy(size_t size, void* dst, const void* src)
{
	return memcpy(dst, src, size);
}

inline void cc_xor(size_t size, void* result, const void* left, const void* right)
{
	size_t i;
	uint8_t* res8 = (uint8_t*) result;
	const uint8_t* l8 = (const uint8_t*) left;
	const uint8_t* r8 = (const uint8_t*) right;

	for (i = 0; i < size; i++)
		res8[i] = l8[i] ^ r8[i];
}

// memcmp in const time
int cc_cmp_safe(size_t num, const void* ptr1, const void* ptr2);

// return (s) ? a : b // in const time
void* cc_muxp(int s, const void *a, const void *b);

#define CC_SWAP(a,b) {\
    __typeof__(a) tmp = a;\
	a = b;\
	b = tmp;\
}

// Like the max macro, but params are evaluated only once
#define CC_MAX(a, b) ({\
		__typeof__(a) ax = a;\
		__typeof__(b) bx = b;\
		ax > bx ? ax : bx;\
})

// Like the min macro, but params are evaluated only once
#define CC_MIN(a, b) ({\
		__typeof__(a) ax = a;\
		__typeof__(b) bx = b;\
		ax < bx ? ax : bx;\
})

#endif

