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

#ifndef _CORECRYPTO_CCSHA2_H
#define _CORECRYPTO_CCSHA2_H

#include <corecrypto/ccdigest.h>

const struct ccdigest_info *ccsha224_di(void);
const struct ccdigest_info *ccsha256_di(void);
const struct ccdigest_info *ccsha384_di(void);
const struct ccdigest_info *ccsha512_di(void);

#define CCSHA256_BLOCK_SIZE  64
#define	CCSHA256_OUTPUT_SIZE 32
#define	CCSHA256_STATE_SIZE  32

extern const struct ccdigest_info ccsha256_ltc_di;
extern const uint32_t ccsha256_K[64];

#define	CCSHA224_OUTPUT_SIZE 28
extern const struct ccdigest_info ccsha224_ltc_di;

#define CCSHA512_BLOCK_SIZE  128
#define	CCSHA512_OUTPUT_SIZE  64
#define	CCSHA512_STATE_SIZE   64
extern const struct ccdigest_info ccsha512_ltc_di;

#define	CCSHA384_OUTPUT_SIZE  48
extern const struct ccdigest_info ccsha384_ltc_di;

#endif

