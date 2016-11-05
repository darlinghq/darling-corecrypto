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

#include <corecrypto/ccdigest.h>
#include <string.h>

void ccdigest(const struct ccdigest_info* di, unsigned long len, const void* data, void* digest)
{
	ccdigest_di_decl(di, context);

	ccdigest_init(di, context);
	ccdigest_update(di, context, len, data);
	ccdigest_final(di, context, digest);

	ccdigest_di_clear(di, context);
}

void ccdigest_init(const struct ccdigest_info* di, ccdigest_ctx_t ctx)
{
	ccdigest_nbits(di, ctx) = 0;
	ccdigest_num(di, ctx) = 0;
	memcpy(ccdigest_state(di, ctx), di->initial_state, di->state_size);
}

static inline void ccdigest_submit_block(const struct ccdigest_info* di, ccdigest_ctx_t ctx, int nblocks, const void* data)
{
	di->compress(ccdigest_state(di, ctx), nblocks, data);
	ccdigest_nbits(di, ctx) += nblocks * di->block_size * 8;
}

void ccdigest_update(const struct ccdigest_info* di, ccdigest_ctx_t ctx, unsigned long len, const void* data)
{
	const uint8_t* ptr = (const uint8_t*) data;

	while (len > 0)
	{
		int buffered = ccdigest_num(di, ctx);
		// Do we have leftover bytes from last time?
		if (buffered > 0)
		{
			int tocopy = di->block_size - buffered;
			if (tocopy > len)
				tocopy = len;

			memcpy(ccdigest_data(di, ctx) + buffered, ptr, tocopy);

			buffered += tocopy;
			len -= tocopy;
			ptr += tocopy;

			ccdigest_num(di, ctx) = buffered;

			if (buffered == di->block_size)
			{
				// Submit to compression
				ccdigest_submit_block(di, ctx, 1, ccdigest_data(di, ctx));
				ccdigest_num(di, ctx) = 0; // nothing left in buffer
			}
		}
		else if (len >= di->block_size)
		{
			int nblocks = len / di->block_size;
			int bytes = nblocks * di->block_size;

			ccdigest_submit_block(di, ctx, nblocks, ptr);
			len -= bytes;
			ptr += bytes;
		}
		else
		{
			// Buffer the remaining data
			memcpy(ccdigest_data(di, ctx), ptr, len);
			ccdigest_num(di, ctx) = len;
			break;
		}
	}
}


int ccdigest_test(const struct ccdigest_info* di, unsigned long len, const void* data, const void* digest)
{
	return ccdigest_test_chunk(di, len, data, digest, len);
}

int ccdigest_test_chunk(const struct ccdigest_info* di, unsigned long len, const void* data, const void *digest, unsigned long chunk)
{
	const uint8_t* ptr = (const uint8_t*) data;
	unsigned long done;
	unsigned char* calc_digest = (unsigned char*) __builtin_alloca(di->output_size);
	ccdigest_di_decl(di, context);

	ccdigest_init(di, context);

	for (done = 0; done < len; done += chunk)
	{
		ccdigest_update(di, context, chunk, ptr);
		ptr += chunk;
	}

	ccdigest_final(di, context, calc_digest);

	ccdigest_di_clear(di, context);
	return memcmp(calc_digest, digest, di->output_size) == 0;
}

int ccdigest_test_vector(const struct ccdigest_info* di, const struct ccdigest_vector* v)
{
	return ccdigest_test(di, v->len, v->message, v->digest);
}

int ccdigest_test_chunk_vector(const struct ccdigest_info* di, const struct ccdigest_vector* v, unsigned long chunk)
{
	return ccdigest_test_chunk(di, v->len, v->message, v->digest, chunk);
}

