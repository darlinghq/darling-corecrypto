/*
 * Copyright (c) 2026 Lubos Dolezel
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

/*
 * Internal multi-precision helpers shared by the modular exponentiation
 * behind cczp_power, ccz_expmod and ccdh. Nothing here is exported.
 *
 * Numbers are little-endian arrays of cc_unit, as everywhere else in
 * corecrypto. Unless a comment says otherwise, every function's running time
 * and memory access pattern depend only on the unit counts it is given, never
 * on the values of the operands.
 */

#ifndef CC_PRIVATE_DBN_H
#define CC_PRIVATE_DBN_H

#include <corecrypto/ccn.h>

#define DBN_HIDDEN __attribute__((visibility("hidden")))

/* r = a + b over n units; returns the carry out (0 or 1). */
DBN_HIDDEN cc_unit dbn_add(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *b);

/* r = a - b over n units; returns the borrow out (0 or 1). */
DBN_HIDDEN cc_unit dbn_sub(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *b);

/* 1 if the n-unit numbers a and b are equal, else 0. */
DBN_HIDDEN cc_unit dbn_equal(cc_size n, const cc_unit *a, const cc_unit *b);

/* 1 if a < b (n units each), else 0. */
DBN_HIDDEN cc_unit dbn_less(cc_size n, const cc_unit *a, const cc_unit *b);

/* 1 if the n-unit number a is zero, else 0. */
DBN_HIDDEN cc_unit dbn_is_zero(cc_size n, const cc_unit *a);

/*
 * Long division with a remainder, one dividend bit at a time:
 *   r = a mod m (nm units), and q = a div m (na units) when q is not NULL.
 * m must not be zero. r and q must not overlap a, m or each other.
 * Slow (na * CCN_UNIT_BITS steps of nm units), but constant time in a and m.
 */
DBN_HIDDEN void dbn_divrem(cc_size na, cc_unit *q, cc_size nm, cc_unit *r,
                           const cc_unit *a, const cc_unit *m);

/*
 * r = b^e mod m.
 *   r, b, m: n units; b need not be reduced. e: ne units (ne may be 0).
 *   r may alias b; it must not alias e or m.
 * The time and memory accesses depend on n, ne and on whether m is odd, not
 * on the values of b and e. Odd moduli use Montgomery multiplication, even
 * moduli a much slower division-based multiplication.
 * Returns 0, or -1 when m is zero or no memory is available (r is then 0).
 */
DBN_HIDDEN int dbn_modexp(cc_size n, cc_unit *r, const cc_unit *b,
                          cc_size ne, const cc_unit *e, const cc_unit *m);

#endif /* CC_PRIVATE_DBN_H */
