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
 * Constant-time modular exponentiation for corecrypto.
 *
 * Algorithms, all textbook:
 * - Montgomery multiplication in the "coarsely integrated operand scanning"
 *   form (P. L. Montgomery, "Modular Multiplication Without Trial Division",
 *   Math. Comp. 44, 1985; C. K. Koc, T. Acar, B. S. Kaliski, "Analyzing and
 *   Comparing Montgomery Multiplication Algorithms", IEEE Micro 16(3), 1996;
 *   Handbook of Applied Cryptography, algorithm 14.36).
 * - Fixed 4-bit window exponentiation (HAC 14.82 with every window used),
 *   reading the table with a full scan and masks so the exponent's digits do
 *   not show in the memory access pattern.
 * - The inverse of the modulus modulo 2^w by Newton iteration
 *   (x <- x * (2 - m * x) doubles the number of correct low bits).
 * - Restoring binary long division for reductions by arbitrary moduli.
 */

#include <corecrypto/private/dbn.h>
#include <corecrypto/cc.h>
#include <stdlib.h>
#include <string.h>

#if CCN_UNIT_SIZE == 8
typedef unsigned __int128 dbn_wide;
#else
typedef uint64_t dbn_wide;
#endif

#define UNIT_BITS ((unsigned)CCN_UNIT_BITS)
#define WINDOW_BITS 4
#define WINDOW_SIZE (1u << WINDOW_BITS)

/* all ones for bit == 1, zero for bit == 0 */
static inline cc_unit mask_of(cc_unit bit)
{
	return (cc_unit)0 - bit;
}

/* 1 if x != 0, else 0 */
static inline cc_unit nonzero_unit(cc_unit x)
{
	return (x | ((cc_unit)0 - x)) >> (UNIT_BITS - 1);
}

/* r = mask ? a : b, for a mask that is all ones or zero */
static void choose(cc_size n, cc_unit *r, cc_unit mask, const cc_unit *a, const cc_unit *b)
{
	for (cc_size i = 0; i < n; i++)
		r[i] = (a[i] & mask) | (b[i] & ~mask);
}

cc_unit dbn_add(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *b)
{
	cc_unit carry = 0;
	for (cc_size i = 0; i < n; i++) {
		dbn_wide sum = (dbn_wide)a[i] + b[i] + carry;
		r[i] = (cc_unit)sum;
		carry = (cc_unit)(sum >> UNIT_BITS);
	}
	return carry;
}

cc_unit dbn_sub(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *b)
{
	cc_unit borrow = 0;
	for (cc_size i = 0; i < n; i++) {
		dbn_wide diff = (dbn_wide)a[i] - b[i] - borrow;
		r[i] = (cc_unit)diff;
		borrow = (cc_unit)(diff >> UNIT_BITS) & 1;
	}
	return borrow;
}

cc_unit dbn_equal(cc_size n, const cc_unit *a, const cc_unit *b)
{
	cc_unit diff = 0;
	for (cc_size i = 0; i < n; i++)
		diff |= a[i] ^ b[i];
	return 1 ^ nonzero_unit(diff);
}

cc_unit dbn_less(cc_size n, const cc_unit *a, const cc_unit *b)
{
	/* the borrow of a - b, without storing the difference */
	cc_unit borrow = 0;
	for (cc_size i = 0; i < n; i++) {
		dbn_wide diff = (dbn_wide)a[i] - b[i] - borrow;
		borrow = (cc_unit)(diff >> UNIT_BITS) & 1;
	}
	return borrow;
}

cc_unit dbn_is_zero(cc_size n, const cc_unit *a)
{
	cc_unit any = 0;
	for (cc_size i = 0; i < n; i++)
		any |= a[i];
	return 1 ^ nonzero_unit(any);
}

/*
 * v holds the n+1 unit value (top : v[0..n-1]), which must be below 2 * m.
 * Leaves v mod m in v[0..n-1]. scratch: n units.
 */
static void subtract_if_not_below(cc_size n, cc_unit *v, cc_unit top, const cc_unit *m, cc_unit *scratch)
{
	cc_unit borrow = dbn_sub(n, scratch, v, m);
	/* (top : v) >= m exactly when the top unit is set or v - m did not borrow */
	cc_unit take = nonzero_unit(top) | (borrow ^ 1);
	choose(n, v, mask_of(take), scratch, v);
}

/* r = 2 * r + bit over n units; returns the bit shifted out at the top */
static cc_unit double_plus_bit(cc_size n, cc_unit *r, cc_unit bit)
{
	cc_unit carry = bit;
	for (cc_size i = 0; i < n; i++) {
		cc_unit out = r[i] >> (UNIT_BITS - 1);
		r[i] = (r[i] << 1) | carry;
		carry = out;
	}
	return carry;
}

void dbn_divrem(cc_size na, cc_unit *q, cc_size nm, cc_unit *r,
                const cc_unit *a, const cc_unit *m)
{
	cc_unit scratch[nm];

	memset(r, 0, ccn_sizeof_n(nm));
	if (q)
		memset(q, 0, ccn_sizeof_n(na));

	for (cc_size i = na * UNIT_BITS; i-- > 0;) {
		cc_unit bit = (a[i / UNIT_BITS] >> (i % UNIT_BITS)) & 1;
		/* r < m, so 2 * r + bit < 2 * m: one conditional subtraction */
		cc_unit top = double_plus_bit(nm, r, bit);
		cc_unit borrow = dbn_sub(nm, scratch, r, m);
		cc_unit take = top | (borrow ^ 1);
		choose(nm, r, mask_of(take), scratch, r);
		if (q)
			q[i / UNIT_BITS] |= take << (i % UNIT_BITS);
	}

	cc_clear(sizeof(scratch), scratch);
}

/* -m0^-1 mod 2^w for an odd m0 */
static cc_unit negated_unit_inverse(cc_unit m0)
{
	/* m0 * m0 == 1 mod 8 for odd m0, so x starts with 3 correct bits */
	cc_unit x = m0;
	for (int i = 0; i < 5; i++)
		x *= 2 - m0 * x;
	return (cc_unit)0 - x;
}

struct modexp_state {
	cc_size n;
	const cc_unit *m;
	int montgomery;     /* m is odd */
	cc_unit m_neg_inv;  /* -m^-1 mod 2^w, Montgomery only */
	cc_unit *scratch;   /* 2n + 2 units */
};

/*
 * Montgomery product r = a * b / 2^(n*w) mod m, for a * b < m * 2^(n*w)
 * (in particular a < 2^(n*w) and b < m). r may alias a or b.
 */
static void mont_mul(const struct modexp_state *st, cc_unit *r, const cc_unit *a, const cc_unit *b)
{
	const cc_size n = st->n;
	const cc_unit *m = st->m;
	cc_unit *t = st->scratch; /* n + 2 units of accumulator */
	cc_unit *diff = st->scratch + n + 2;

	memset(t, 0, ccn_sizeof_n(n + 2));

	for (cc_size i = 0; i < n; i++) {
		/* t += a * b[i] */
		cc_unit carry = 0;
		for (cc_size j = 0; j < n; j++) {
			dbn_wide acc = (dbn_wide)a[j] * b[i] + t[j] + carry;
			t[j] = (cc_unit)acc;
			carry = (cc_unit)(acc >> UNIT_BITS);
		}
		dbn_wide acc = (dbn_wide)t[n] + carry;
		t[n] = (cc_unit)acc;
		t[n + 1] = (cc_unit)(acc >> UNIT_BITS);

		/* t = (t + u * m) / 2^w, with u chosen so the low unit cancels */
		cc_unit u = t[0] * st->m_neg_inv;
		acc = (dbn_wide)u * m[0] + t[0];
		carry = (cc_unit)(acc >> UNIT_BITS);
		for (cc_size j = 1; j < n; j++) {
			acc = (dbn_wide)u * m[j] + t[j] + carry;
			t[j - 1] = (cc_unit)acc;
			carry = (cc_unit)(acc >> UNIT_BITS);
		}
		acc = (dbn_wide)t[n] + carry;
		t[n - 1] = (cc_unit)acc;
		t[n] = t[n + 1] + (cc_unit)(acc >> UNIT_BITS);
	}

	/* t < 2m now */
	cc_unit borrow = dbn_sub(n, diff, t, m);
	cc_unit take = nonzero_unit(t[n]) | (borrow ^ 1);
	choose(n, r, mask_of(take), diff, t);
}

/* plain product r = a * b mod m for a, b < m (even moduli). r may alias a or b. */
static void plain_mul(const struct modexp_state *st, cc_unit *r, const cc_unit *a, const cc_unit *b)
{
	const cc_size n = st->n;
	cc_unit *product = st->scratch; /* 2n units */

	memset(product, 0, ccn_sizeof_n(2 * n));
	for (cc_size i = 0; i < n; i++) {
		cc_unit carry = 0;
		for (cc_size j = 0; j < n; j++) {
			dbn_wide acc = (dbn_wide)a[j] * b[i] + product[i + j] + carry;
			product[i + j] = (cc_unit)acc;
			carry = (cc_unit)(acc >> UNIT_BITS);
		}
		product[i + n] = carry;
	}
	dbn_divrem(2 * n, NULL, n, r, product, st->m);
}

static void mod_mul(const struct modexp_state *st, cc_unit *r, const cc_unit *a, const cc_unit *b)
{
	if (st->montgomery) /* the parity of the modulus is public */
		mont_mul(st, r, a, b);
	else
		plain_mul(st, r, a, b);
}

/* copy table entry idx to out, reading every entry */
static void table_read(cc_size n, cc_unit *out, const cc_unit *table, cc_unit idx)
{
	memset(out, 0, ccn_sizeof_n(n));
	for (cc_unit k = 0; k < WINDOW_SIZE; k++) {
		cc_unit hit = mask_of(1 ^ nonzero_unit(k ^ idx));
		const cc_unit *entry = table + k * n;
		for (cc_size j = 0; j < n; j++)
			out[j] |= entry[j] & hit;
	}
}

int dbn_modexp(cc_size n, cc_unit *r, const cc_unit *b,
               cc_size ne, const cc_unit *e, const cc_unit *m)
{
	if (n == 0)
		return -1;
	if (dbn_is_zero(n, m)) {
		memset(r, 0, ccn_sizeof_n(n));
		return -1;
	}

	/* table | acc | pick | one | scratch */
	const cc_size total = WINDOW_SIZE * n + 3 * n + (2 * n + 2);
	cc_unit *ws = malloc(ccn_sizeof_n(total));
	if (!ws) {
		memset(r, 0, ccn_sizeof_n(n));
		return -1;
	}

	cc_unit *table = ws;
	cc_unit *acc = table + WINDOW_SIZE * n;
	cc_unit *pick = acc + n;
	cc_unit *one = pick + n;

	struct modexp_state st = {
		.n = n,
		.m = m,
		.montgomery = (int)(m[0] & 1),
		.scratch = one + n,
	};

	memset(one, 0, ccn_sizeof_n(n));
	one[0] = 1;

	if (st.montgomery) {
		st.m_neg_inv = negated_unit_inverse(m[0]);

		/* pick = 2^(2nw) mod m by doubling 1 (reduced first, for m == 1) */
		cc_unit *rr = pick;
		memset(rr, 0, ccn_sizeof_n(n));
		rr[0] = 1;
		subtract_if_not_below(n, rr, 0, m, st.scratch);
		for (cc_size i = 0; i < 2 * n * UNIT_BITS; i++) {
			cc_unit top = double_plus_bit(n, rr, 0);
			subtract_if_not_below(n, rr, top, m, st.scratch);
		}

		/* table[0] = 1 * R mod m, table[1] = b * R mod m */
		mont_mul(&st, table, rr, one);
		mont_mul(&st, table + n, b, rr);
	} else {
		dbn_divrem(n, NULL, n, table, one, m);
		dbn_divrem(n, NULL, n, table + n, b, m);
	}

	for (cc_unit k = 2; k < WINDOW_SIZE; k++)
		mod_mul(&st, table + k * n, table + (k - 1) * n, table + n);

	/* left to right over every window of e, leading zero windows included */
	memcpy(acc, table, ccn_sizeof_n(n));
	for (cc_size w = ne * (UNIT_BITS / WINDOW_BITS); w-- > 0;) {
		for (int s = 0; s < WINDOW_BITS; s++)
			mod_mul(&st, acc, acc, acc);
		size_t bit = w * WINDOW_BITS;
		cc_unit digit = (e[bit / UNIT_BITS] >> (bit % UNIT_BITS)) & (WINDOW_SIZE - 1);
		table_read(n, pick, table, digit);
		mod_mul(&st, acc, acc, pick);
	}

	if (st.montgomery)
		mont_mul(&st, r, acc, one); /* leave the Montgomery domain */
	else
		memcpy(r, acc, ccn_sizeof_n(n));

	cc_clear(ccn_sizeof_n(total), ws);
	free(ws);
	return 0;
}
