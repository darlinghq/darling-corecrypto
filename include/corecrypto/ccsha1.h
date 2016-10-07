/*
 * Copyright (c) 2016 Lubos Dolezel
 *
 * This file is part of Darling CoreCrypto.
 *
 * Neo4j is free software: you can redistribute it and/or modify
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

#ifndef _CORECRYPTO_CCSHA1_H
#define _CORECRYPTO_CCSHA1_H

#include <corecrypto/ccdigest.h>
#include <corecrypto/cc_config.h>

#define CCSHA1_BLOCK_SIZE   64
#define CCSHA1_OUTPUT_SIZE  20
#define CCSHA1_STATE_SIZE   20

const struct ccdigest_info *ccsha1_di(void);

extern const uint32_t ccsha1_initial_state[5];

void ccsha1_final(const struct ccdigest_info *di, ccdigest_ctx_t,
                  unsigned char *digest);

extern const struct ccdigest_info ccsha1_ltc_di;
extern const struct ccdigest_info ccsha1_eay_di;

#endif

