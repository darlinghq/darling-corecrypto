#include <corecrypto/ccn.h>
#include <stdio.h>
#include <stdlib.h>

cc_size ccn_n(cc_size n, const cc_unit *s) {
    // Little-endian, so the leading 0 units go at the end.

    // Hopefully constant time,
    cc_size last = 0;
    for (cc_size i = 0; i < n; i++) {
        if (s[i] != 0) {
            last = i;
        }
    }
    return last + 1;
}

/*
 * shift over k bits in direction of least significance
 */
cc_unit ccn_shift_right(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
	cc_unit carry = 0;
	cc_unit temp;

	for (int i = n-1; i >= 0; i--)
	{
		temp = s[i];
		r[i] = temp >> k;
		r[i] |= carry;
		carry = temp << (CCN_UNIT_BITS - k);
	}
	return carry;
}
void ccn_shift_right_multi(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

/*
 * k must be <= CCN_UNIT_BITS
 *
 * r and s may be equal
 */
cc_unit ccn_shift_left(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
	cc_unit carry = 0;
	cc_unit temp;

	for (int i = 0; i < n; i++)
	{
		temp = s[i];
		r[i] = temp << k;
		r[i] |= carry;
		carry = temp >> (CCN_UNIT_BITS - k);
	}
	return carry;
}

void ccn_shift_left_multi(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccn_bitlen(cc_size n, const cc_unit *s) {
    cc_size used = ccn_n(n, s);

    if (used == 0) {
        // None of the units are used <=> s == 0.
        return 0;
    }

    cc_unit last_used_unit = s[used - 1];

    // CLZ counts the number of leading zero bits in the
    // the last unit that we know not to be all zeroes.
    return used * CCN_UNIT_SIZE - __builtin_clzl(last_used_unit);
}

size_t ccn_trailing_zeros(cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

// n is in bits
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
#if DEBUG
	printf("DARLING CRYPTO IMPL: %s\n", __PRETTY_FUNCTION__);
#endif
	// Assumes these are all unsigned, if signed, look at first bit
	// for sign
	
	// TODO: handle when bits isn't aligned with a cc_unit
	cc_size unit_count = ccn_nof(n);
#if DEBUG
	cc_size unit_bytes = ccn_sizeof_n(unit_count);
	printf("passed in bits: %zu, resulting units: %zu, bytes: %zu\n", n, unit_count, unit_bytes);
#endif
	for (cc_size i = 0; i < unit_count; i++)
	{
#if DEBUG
		printf("i: %zu, offset: %zu\n", i, unit_count-i-1);
#endif
		int offset = unit_count-i-1;
		if (s[offset] < t[offset])
		{
			return -1;
		}
		else if (s[offset] > t[offset])
		{
			return 1;
		}
	}
	return 0;
}

/*
 * r = s - t
 */
cc_unit ccn_sub(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
	cc_unit *s_copy = malloc(ccn_sizeof_n(n));
	memcpy(s_copy, s, ccn_sizeof_n(n));
	for (cc_size i = 0; i < n; i++)
	{
		s_copy[i] = ~s_copy[i];
	}
	ccn_add1(n, s_copy, s_copy, 1);
	ccn_add(n, s_copy, s_copy, t);
	// Remove greatest significance bit
	s_copy[n-1] &= CCN_UNIT_MASK >> 1;
	memcpy(r, s_copy, ccn_sizeof_n(n));
}

cc_unit ccn_abs(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_sub1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_add1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v)
{
	cc_size i;
	cc_unit last = s[n-1];
	cc_unit current;
	memcpy(r, s, ccn_sizeof_n(n));
	for (i = 0; i < n-1; i++)
	{
		current = r[i];
		// Handle overflow
		if (current + v < current)
		{
			r[i] = CCN_UNIT_MASK;
			v = current+v;

		}
		else
		{
			r[i] = current + v;
			return 0;
		}
	}
	return v;

}

void ccn_lcm(cc_size n, cc_unit *r2n, const cc_unit *s, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_mul(cc_size n, cc_unit *r_2n, const cc_unit *s, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_mul_ws(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t, cc_ws_t ws) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_mul1(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit v) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_addmul1(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit v) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_gcd(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_gcdn(cc_size rn, cc_unit *r, cc_size sn, const cc_unit *s, cc_size tn, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccn_read_uint(cc_size n, cc_unit *r, size_t data_size, const uint8_t *data) {

    // The size of r (n) is passed as the number of cc_unit-s,
    // so we use ccn_sizeof_n() to get its actual byte size.
    size_t sizeof_r = ccn_sizeof_n(n);

    // Start by pre-zeroing r.
    memset(r, 0, sizeof_r);

    // Leading zero bytes are insignificant in big endian,
    // so we can safely skip them.
    for (; data_size > 0 && *data == 0; data_size--, data++);

    // Now, data_size is the actual number of bytes it will
    // take to write out the data. Return -1 if we don't have
    // that much space.
    if (data_size > sizeof_r) {
        return -1;
    }

    // We treat r as little-endian with respect to the order
    // of the cc_unit-s, but the cc_unit-s themselves are
    // native-endian (which still means little-endian on
    // i386/x64).
    for (long ind = data_size - 1; ind >= 0; r++) {
        for (int i = 0; i < CCN_UNIT_SIZE && ind >= 0; i++, ind--) {
            cc_unit c = data[ind];
            *r |= c << (i * 8);
        }
    }

    return 0;
}

size_t ccn_write_uint_size(cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_write_uint(cc_size n, const cc_unit *s, size_t out_size, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccn_write_int_size(cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_write_int(cc_size n, const cc_unit *s, size_t out_size, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_set(cc_size n, cc_unit *r, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_zero_multi(cc_size n, cc_unit *r, ...) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_print(cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	// Just print each cc_unit in order for now
	printf("size: %zu\n", n);
	for (int i = 0; i < n; i++)
	{
		printf("todo");
		//printf("%llu ", s[i]);
	}
	printf("\n");
}

void ccn_lprint(cc_size n, const char *label, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccn_random_bits(cc_size nbits, cc_unit *r, struct ccrng_state *rng) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_make_recip(cc_size nd, cc_unit *recip, const cc_unit *d) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccn_div_euclid(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccn_div_use_recip(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d, const cc_unit *recip_d) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
