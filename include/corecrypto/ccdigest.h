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

#ifndef _CORECRYPTO_CCDIGEST_H
#define _CORECRYPTO_CCDIGEST_H

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
 
struct ccdigest_ctx // followed by struct ccdigest_state
{
	union
	{
		uint8_t u8;
		uint32_t u32;
		uint64_t u64; // holds nbits (amount of bits compressed in total)
		cc_unit ccn; // also 64bits
	} state;
}
__attribute((aligned(8)));

typedef union
{
	struct ccdigest_ctx *hdr;
} ccdigest_ctx_t
__attribute__((transparent_union));

struct ccdigest_state
{
	union
	{
		uint8_t u8;
		uint32_t u32;
		uint64_t u64;
		cc_unit ccn; // also 64bits
	} state;
}
__attribute((aligned(8)));
// ccdigest_state is followed by block_size of buffer

typedef union
{
	struct ccdigest_state *hdr;
	struct ccdigest_ctx *_ctx;
	ccdigest_ctx_t _ctxt;
} ccdigest_state_t
__attribute__((transparent_union));

struct ccdigest_info
{
	unsigned long output_size;
	unsigned long state_size;
	unsigned long block_size;
	unsigned long oid_size;
	unsigned char* oid;
	const void* initial_state;
	void(*compress)(ccdigest_state_t state, unsigned long nblocks, const void* data);
	void(*final)(const struct ccdigest_info* di, ccdigest_ctx_t ctx, unsigned char* digest);
};


void ccdigest_init(const struct ccdigest_info* di, ccdigest_ctx_t ctx);

// Submit data to the compress function, block by block
// Incomplete blocks are saved at ccdigest_data(), amount of data stored within is set at ccdigest_num()
void ccdigest_update(const struct ccdigest_info* di, ccdigest_ctx_t ctx, unsigned long len, const void* data);

void ccdigest(const struct ccdigest_info* di, unsigned long len, const void* data, void* digest);

int ccdigest_test(const struct ccdigest_info* di, unsigned long len, const void* data, const void* digest);

int ccdigest_test_chunk(const struct ccdigest_info* di, unsigned long len, const void* data, const void *digest, unsigned long chunk);

struct ccdigest_vector
{
	unsigned long len;
	const void* message;
	const void* digest;
};

int ccdigest_test_vector(const struct ccdigest_info* di, const struct ccdigest_vector* v);
int ccdigest_test_chunk_vector(const struct ccdigest_info* di, const struct ccdigest_vector* v, unsigned long chunk);

#define ccdigest_ctx_size(statesize_, block_size)  ((statesize_) + sizeof(uint64_t) + (block_size) + sizeof(unsigned int))
#define ccdigest_di_size(di)	(ccdigest_ctx_size((di)->state_size, (di)->block_size))

#define ccdigest_ctx_decl(statesize_, block_size, name)  cc_ctx_decl(struct ccdigest_ctx, ccdigest_ctx_size(statesize_, block_size), name)
#define ccdigest_ctx_clear(statesize_, block_size, name) cc_clear(ccdigest_ctx_size(statesize_, block_size), name)

#define ccdigest_di_decl(di, name)  cc_ctx_decl(struct ccdigest_ctx, ccdigest_di_size(di), name)
#define ccdigest_di_clear(di, name) cc_clear(ccdigest_di_size(di), name)

#define ccdigest_state(di, ctx)	((struct ccdigest_state*)((ctx).hdr + 1))
#define ccdigest_state_u8(di, ctx)   ccdigest_u8(ccdigest_state((di), (ctx)))
#define ccdigest_state_u32(di, ctx)  ccdigest_u32(ccdigest_state((di), (ctx)))
#define ccdigest_state_u64(di, ctx)  ccdigest_u64(ccdigest_state((di), (ctx)))
#define ccdigest_state_ccn(di, ctx)  ccdigest_ccn(ccdigest_state((di), (ctx)))
#define ccdigest_nbits(di, ctx)		 ((ccdigest_ctx_t)(ctx)).hdr->state.u64

#define ccdigest_data(di, ctx)		 (&((ccdigest_ctx_t)(ctx)).hdr->state.u8 + (di)->state_size + sizeof(uint64_t))
#define ccdigest_num(di, ctx)		 (*((unsigned int *)(&((ccdigest_ctx_t)(ctx)).hdr->state.u8 + (di)->state_size + sizeof(uint64_t) + (di)->block_size)))

static inline uint8_t* ccdigest_u8(ccdigest_state_t state) { return &state.hdr->state.u8; }
static inline uint32_t* ccdigest_u32(ccdigest_state_t state) { return &state.hdr->state.u32; }
static inline uint64_t* ccdigest_u64(ccdigest_state_t state) { return &state.hdr->state.u64; }
static inline cc_unit* ccdigest_ccn(ccdigest_state_t state) { return &state.hdr->state.ccn; }
#define ccdigest_final(di, ctx, digest) (di)->final(di, ctx, digest)

#define ccdigest_copy_state(di, dst, src) memcpy(dst, src, (di)->state_size)

#define CC_DIGEST_OID_MD2		(const unsigned char*)("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02")
#define CC_DIGEST_OID_MD4		(const unsigned char*)("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x04")
#define CC_DIGEST_OID_MD5		(const unsigned char*)("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05")
#define CC_DIGEST_OID_SHA1		(const unsigned char*)("\x06\x05\x2b\x0e\x03\x02\x1a")
#define CC_DIGEST_OID_SHA224	(const unsigned char*)("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04")
#define CC_DIGEST_OID_SHA256	(const unsigned char*)("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01")
#define CC_DIGEST_OID_SHA384	(const unsigned char*)("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02")
#define CC_DIGEST_OID_SHA512	(const unsigned char*)("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03")
#define CC_DIGEST_OID_RMD128	(const unsigned char*)("\x06\x06\x28\xCF\x06\x03\x00\x32")
#define CC_DIGEST_OID_RMD160	(const unsigned char*)("\x06\x05\x2B\x24\x03\x02\x01")
#define CC_DIGEST_OID_RMD256	(const unsigned char*)("\x06\x05\x2B\x24\x03\x02\x03")
#define CC_DIGEST_OID_RMD320	NULL


#endif

