#include <corecrypto/cczp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

CC_INLINE
void shift_units_right(cc_size n, cc_unit* result, const cc_unit* operand, cc_size count) {
	for (cc_size i = n; i > count; --i) {
		result[(i - 1) - count] = operand[i - 1];
		// we *should* zero the units that will be empty to be 100% correct,
		// but the way this function is used, result may be smaller than `n`
		// for memory efficiency
		//if (i > n - count)
		//	result[i - 1] = 0;
	}
};

CC_INLINE
void shift_units_left(cc_size n, cc_unit* result, const cc_unit* operand, cc_size count) {
	for (cc_size i = 0; i < n - count; --i) {
		result[i + count] = operand[i];
		// same note as in `shift_units_right`
	}
};

void cczp_init(cczp_t zp) {
	zp.zp->mod_prime = &cczp_mod;

	const cc_unit* prime = cczp_prime(zp);
	cc_size n = ccn_n(cczp_n(zp), prime);

	// we're using Knuth's Algorithm D: division of nonnegative integers
	// (see "The Art of Computer Programming (vol. 2)", section 4.3.1)
	// we're operating in base 2^64

	// our dividend
	// equal to `(2^64)^(2 * n)`
	// that is: our base (2^64) to the power of `2 * n`
	cc_unit* pow = __builtin_alloca(ccn_sizeof_n(2 * n + 2));
	memset(pow, 0, ccn_sizeof_n(2 * n + 2));
	pow[2 * n] = 1;

	// our quotient
	// the reciprocal of our modulus, in base 2^64
	cc_unit* recip = __builtin_alloca(ccn_sizeof_n(n + 1));
	memset(recip, 0, ccn_sizeof_n(n + 1));

	// our divisor
	cc_unit* prime_copy = __builtin_alloca(ccn_sizeof_n(n + 1));
	prime_copy[n] = 0;
	memcpy(prime_copy, prime, ccn_sizeof_n(n));

	// 1. normalize
	// make sure that the most significant digit of the divisor
	// is greater than half of the base (greater than `2^63` in this case)
	//
	// for us, that means "eliminate leading zeros", which we do by
	// counting them and shifting all the bits left by that amount
	cc_size shift = __builtin_clzl(prime_copy[n - 1]);
	// the `ccn_shift_*` functions currently have a bug where they will not
	// work correctly when given a 0 as the shift count
	// TODO: fix this
	if (shift > 0) {
		ccn_shift_left_multi(n + 1, prime_copy, prime_copy, shift);
		ccn_shift_left_multi(n + 1, pow, pow, shift);
	}
	
	// note that after normalization, the divisor still has the same number of digits as before
	// but the dividend has a new most significant digit
	//
	// thus, the most significant digit of the divisor is at `n - 1`, but the most significant digit
	// of the dividend is at `(2 * n) + 1`
	//
	// however, for the purposes of the loop counter computation later on,
	// we use the original number of digits for both

	// the base we're using
	// since cc_units have architecture dependent sizes, we use the defined bit mask (which
	// is equal to the base minus 1), and we add 1
	cc_dunit base = CCN_UNIT_MASK;
	base += 1;

	// 2. initialize `j`
	// set `j` equal to the difference in the number of digits between the divisor
	// and the dividend
	//
	// this translates to `(2 * n + 1) - n`, which is just `n + 1`
	// ...plus an extra 1 because we're using an unsigned counter
	//
	// this step also includes:
	// 7. loop on `j`
	for (cc_size i = n + 2; i > 0; --i) {
		cc_size j = i - 1;
		cc_unit* pow_pointer = pow + j;

		// 3. calculate q_hat
		// set q_hat equal to the two most significant digits of the dividend
		// divided by the most significant digit of the divisor
		//
		// also set r_hat equal to the remainder of this operation
		cc_dunit two_digits = ((cc_dunit)pow_pointer[n] << CCN_UNIT_BITS) | (cc_dunit)pow_pointer[n - 1];
		cc_dunit q_hat = two_digits / prime_copy[n - 1];
		cc_dunit r_hat = two_digits % prime_copy[n - 1];

		// (still part of step 3)
		while (true) {
			// if q_hat is greater than or equal to the base
			// OR
			// if q_hat times the second most significant digit of the divisor is
			// greater than r_hat times the base plus the second third most significant digit of the dividend
			// then...
			if (q_hat >= base || (q_hat * prime_copy[n - 2]) > ((r_hat << CCN_UNIT_BITS) | pow_pointer[n - 2])) {
				// ...decrease q_hat by one
				--q_hat;
				// and add the most significant digit of the divisor to r_hat
				r_hat += prime_copy[n - 1];
				// continue performing this test while r_hat is less than the base
				if (r_hat < base)
					continue;
			}
			break;
		}

		// btw, we use variable length arrays here because unlike
		// alloca-allocated memory, they're freed at the end of their
		// scope, and we might loop *a lot* (since we're dependent on
		// the unit count, which we don't control)

		// we only need `n + 1` units because at this point,
		// q_hat is a single unit number, not double unit (and we're only
		// using `n` units of `prime_copy`)
		//
		// however, we need to allocate all the units necessary
		// because `ccn_mul` does a zero for the full 2n
		cc_unit result[2 * n];
		memset(result, 0, ccn_sizeof_n(2 * n));

		cc_unit q_hat_ccn[n];
		memset(q_hat_ccn, 0, ccn_sizeof_n(n));
		q_hat_ccn[0] = (cc_unit)(q_hat & CCN_UNIT_MASK);

		// 4. multiply and subtract
		// subtract `q_hat * divisor` from the t

		// `q_hat * divisor`
		ccn_mul(n, result, q_hat_ccn, prime_copy);

		// note that in the following syntax, the end is exclusive
		// `dividend[j:j + n + 1] -= q_hat * divisor`
		// (a.k.a. subtract `q_hat * divisor` from the digits of the dividend
		// in the range from `j` up to but not including `j + n + 1`)
		//
		// we've already set up pow_pointer to point to `pow + j`
		bool underflow = ccn_sub(n + 1, pow_pointer, pow_pointer, result);

		// 5. test remainder

		// set the j-th digit of the quotient equal to q_hat
		recip[j] = q_hat;

		// if the result of step 4 was negative
		// then...
		if (underflow) {
			// ...decrease the j-th digit of the quotient by 1
			--recip[j];

			// and add one copy of the divisor into the range of digits
			// of the dividend that we subtracted from
			cc_unit tmp[n + 1];
			tmp[n] = 0;
			ccn_set(n, tmp, prime_copy);
			ccn_add(n + 1, pow_pointer, pow_pointer, tmp);
		}
	}

	// step 8 *would* be "unnormalize", but we don't need to do that because we
	// don't need the remainder for our purposes here

	memcpy(CCZP_RECIP(zp), recip, ccn_sizeof_n(n + 1));
}

void cczp_mod(cczp_const_t zp, cc_unit* result, const cc_unit* operand, cc_ws_t ws) {
	// we're implementing Barrett reduction according to the algorithm
	// found in HAC 14.42 (Handbook of Applied Cryptography)
	// http://cacr.uwaterloo.ca/hac/about/chap14.pdf

	// note that `n` here is `k` in the algorithm
	cc_size n = cczp_n(zp);
	const cc_unit* modulus = cczp_prime(zp);
	n = ccn_n(n, modulus);
	const cc_unit* modulus_reciprocal = cczp_recip(zp);
	// `n + 1` because the reciprocal is `n + 1`
	const cc_size normal_size = ccn_sizeof_n(n + 1);
	// `2 * (n + 1)` for the same reason as above
	// but also because we need at most `2 * (n + 1)` units for
	// the multiplication between q_1 (which is at most `n + 1` units large)
	// and modulus_reciprocal (which is at most `n + 1` units large)
	const cc_size double_size = ccn_sizeof_n(2 * (n + 1));

	// `q_1 = floor(x / b^(k - 1))`
	// a.k.a. `q_1 = x >> (k - 1)`
	// note that any and all shifts here are in base 2^64, *not* base 2
	//
	// sizing explanation:
	// operand is at most `2 * n` units large and we're shifting right
	// by `n - 1` units, q_1 is `2 * n - (n - 1)` units large
	// (and `2 * n - (n - 1)` -> `2 * n - n + 1` -> `n + 1`), so q_1 is at most `n + 1` units large
	cc_unit* q_1 = __builtin_alloca(normal_size);
	memset(q_1, 0, normal_size);
	shift_units_right(2 * n, q_1, operand, n - 1);

	// `q_2 = q_1 * u`
	cc_unit* q_2 = __builtin_alloca(double_size);
	memset(q_2, 0, double_size);
	ccn_mul(n + 1, q_2, q_1, modulus_reciprocal);

	// `q_3 = floor(q_2 / b^(k + 1))`
	// a.k.a `q_3 = q_2 >> (k + 1)`
	//
	// sizing explanation:
	// q_2 is at most `2 * (n + 1)` units large and we're shifting right
	// by `n + 1` units, q_3 is `2 * (n + 1) - (n + 1)` units large
	// (and `2 * (n + 1) - (n + 1)` -> `n + 1`), so q_3 is at most `n + 1` units large
	cc_unit* q_3 = __builtin_alloca(normal_size);
	memset(q_3, 0, normal_size);
	shift_units_right(2 * (n + 1), q_3, q_2, n + 1);

	// `operand % b^(k + 1)`, where b is `2^64`,
	// which is the same as extracting the first `k + 1` units
	cc_unit* r_1 = __builtin_alloca(normal_size);
	memset(r_1, 0, normal_size);
	ccn_set(n + 1, r_1, operand);

	cc_unit* m_copy = __builtin_alloca(normal_size);
	memset(m_copy, 0, normal_size);
	memcpy(m_copy, modulus, ccn_sizeof_n(n));

	// `q_3 * m`
	cc_unit* intermediate = __builtin_alloca(double_size);
	memset(intermediate, 0, double_size);
	ccn_mul(n + 1, intermediate, q_3, m_copy);

	// same as for r_1
	cc_unit* r_2 = __builtin_alloca(normal_size);
	memset(r_2, 0, normal_size);
	ccn_set(n + 1, r_2, intermediate);

	// `r = r_1 - r_2`
	cc_unit* r_extra = __builtin_alloca(normal_size);
	memset(r_extra, 0, normal_size);
	bool underflow = ccn_sub(n + 1, r_extra, r_1, r_2);

	// `if r < 0`
	if (underflow) {
		for (cc_size i = 0; i < n + 1; ++i)
			r_extra[i] = ~r_extra[i];

		ccn_add1(n + 1, r_extra, r_extra, 1);
	}

	// `while r >= m`
	while (ccn_cmp(n + 1, r_extra, m_copy) >= 0) {
		// `r = r - m`
		ccn_sub(n + 1, r_extra, r_extra, m_copy);
	}

	// the remainder should now fit in to n units
	// copy it into the result vector
	memcpy(result, r_extra, ccn_sizeof_n(n));
}

/*
 * r = (m^e) mod CCZP_PRIME(zp)
 *
 * Implementation guide: https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
 *
 * zp:	ZP data structure
 * r:	Result pointer, cc_unit array size CCZP_N(zp)
 * m:	Message, also size CCZP_N(zp)
 * e:	Exponent, also size CCZP_N(zp)
 */
void cczp_power(cczp_const_t zp, cc_unit* r, const cc_unit* m, const cc_unit* e) {
	/*
		function modular_pow(base, exponent, modulus) is
			if modulus = 1 then
				return 0
			Assert :: (modulus - 1) * (modulus - 1) does not overflow base
			result := 1
			base := base mod modulus
			while exponent > 0 do
				if (exponent mod 2 == 1) then
					result := (result * base) mod modulus
				exponent := exponent >> 1
				base := (base * base) mod modulus
			return result
	*/
	cc_unit* base = NULL;
	cc_ws ws = { .start = NULL, .end = NULL };
	cc_unit* e_copy = NULL;
	cc_unit* intermediate = NULL;

	cc_size full_n = cczp_n(zp);
	cc_size full_size = ccn_sizeof_n(full_n);

	memset(r, 0, full_size);

	const cc_unit* mod = cczp_prime(zp);
	cc_size mod_n = ccn_n(full_n, mod);

	// if modulus == 1, return 0
	//
	// we *should* copy 1 into a ccn and use
	// ccn_cmp, but this is faster and ccn's are guaranteed
	// to be little-endian so it works well
	if (mod_n == 1 && mod[0] == 1)
		return;

	// allocated: n * 2
	// max ever used: n
	base = __builtin_alloca(full_size * 2);
	memset(base, 0, full_size * 2);
	memcpy(base, m, full_size);

	// result = 1
	r[0] = 1;

	// create a workspace
	// use a workspace size 2n+1 because ws.end is non-inclusive end pointer
	ws.start = __builtin_alloca(ccn_sizeof_n(full_n * 2 + 1));
	ws.end = ws.start + ccn_sizeof_n(full_n * 2);

	// base = base mod modulus
	cczp_mod_prime(zp)(zp, base, base, &ws);

	e_copy = __builtin_alloca(full_size);
	memcpy(e_copy, e, full_size);

	intermediate = __builtin_alloca(full_size * 2);
	memset(intermediate, 0, full_size * 2);

	// while exponent > 0
	while (ccn_n(full_n, e_copy) > 1 || e_copy[0] > 0) {
		// if (exponent mod 2 == 1)
		//
		// `e mod 2` == `e & 1`
		if (ccn_bit(e_copy, 0)) {
			// result = (result * base) mod modulus
			memset(intermediate, 0, full_size * 2);
			ccn_mul(full_n, intermediate, r, base);
			cczp_mod_prime(zp)(zp, r, intermediate, &ws);
		}

		// exponent = exponent >> 1
		ccn_shift_right(full_n, e_copy, e_copy, 1);

		// base = (base * base) mod modulus
		memset(intermediate, 0, full_size * 2);
		ccn_mul(full_n, intermediate, base, base);
		cczp_mod_prime(zp)(zp, base, intermediate, &ws);
	}
}
