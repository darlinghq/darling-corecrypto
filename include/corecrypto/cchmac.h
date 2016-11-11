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

#ifndef _CORECRYPTO_CCHMAC_H_
#define _CORECRYPTO_CCHMAC_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>

void cchmac(const struct ccdigest_info *di, unsigned long key_len, const void *key, unsigned long data_len, const void *data, unsigned char *mac);

#endif /* _CORECRYPTO_CCHMAC_H_ */
