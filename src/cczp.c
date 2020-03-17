#include <corecrypto/cczp.h>
#include <stdio.h>
#include <stdlib.h>

void cczp_init(cczp_t zp)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif
	cc_unit *recip = CCZP_RECIP(zp);
	memset(recip, 0, ccn_sizeof_n(CCZP_N(zp)));
	zp.zp->mod_prime = &cczp_mod;
}

void cczp_mod(cczp_const_t zp, cc_unit* r, const cc_unit* a, cc_ws_t ws) {
	// fast general purpose mod algorithm based on https://stackoverflow.com/a/980903
	// the pseudocode is basically this:
	/*
		function mod(a, b) {
			let s = b
			while (s <= a) {
				s <<= 1
			}
			let r = a
			while (r >= b) {
				s >>= 1
				if (s <= r) {
					r -= s
				}
			}
			return r
		}
	*/
	// lol btw that is valid javascript

	const cc_size n = cczp_n(zp);
	const cc_unit* b = cczp_prime(zp);
	const cc_size a_bits = ccn_bitlen(n * 2, a);
	const cc_size b_bits = ccn_bitlen(n, b);

	// the extra bit is to make sure we're able to make s greater than a
	const cc_size extra_bits = a_bits + 1;
	const cc_size extra_n = ccn_nof(extra_bits);
	const cc_size extra_size = ccn_sizeof(extra_bits);

	const cc_size size = ccn_sizeof_n(n);

	cc_unit* s = NULL;
	cc_unit* r_extra = NULL;
	cc_unit* b_extra = NULL;

	if (b_bits > a_bits) {
		memcpy(r, a, ccn_sizeof_n(n));
		return;
	} else if (a_bits == b_bits) {
		int cmp = ccn_cmp(n, a, b);
		if (cmp < 0) {
			memcpy(r, a, ccn_sizeof_n(n));
			return;
		} else if (cmp == 0) {
			memset(r, 0, ccn_sizeof_n(n));
			r[0] = 1;
			return;
		}
	}

	// at this point, the following is guaranteed to be true:
	//   - a > b
	//   - a_n >= b_n
	//   - a_bits >= b_bits

	// now we copy everyone into bigger vectors to save cycles later on
	// (because we won't have to calculate how many units are currently used)

	b_extra = __builtin_alloca(extra_size);

	memset(b_extra, 0, extra_size);
	memcpy(b_extra, b, size);

	s = __builtin_alloca(extra_size);

	// let s = b
	memcpy(s, b_extra, extra_size);

	// while (s <= a)
	while (ccn_cmp(extra_n, s, a) <= 0) {
		// s <<= 1
		ccn_shift_left(extra_n, s, s, 1);
	}

	r_extra = __builtin_alloca(extra_size);

	// let r = a
	memcpy(r_extra, a, extra_size);

	// while (r <= b)
	while (ccn_cmp(extra_n, r_extra, b_extra) >= 0) {
		// s >>= 1
		ccn_shift_right(extra_n, s, s, 1);
		// if (s <= r)
		if (ccn_cmp(extra_n, s, r_extra) <= 0) {
			// r -= s
			ccn_sub(extra_n, r_extra, r_extra, s);
		}
	}

	// return r
	memcpy(r, r_extra, size);
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
