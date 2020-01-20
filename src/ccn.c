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

/*
 * Compare s to t, each of length n units
 *
 * Returns 1 if s > t
 * Returns 0 if s == t
 * Returns -1 if s < t
 */
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t)
{
	for (int i = n-1; i >= 0; i--)
	{
		if (s[i] < t[i])
		{
			return -1;
		}
		else if (s[i] > t[i])
		{
			return 1;
		}
	}
	return 0;
}

/*
 * r = s - t
 *
 * Implemented using https://en.wikipedia.org/wiki/Method_of_complements
 *
 */
cc_unit ccn_sub(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t)
{
	// Compare to determine if there will be underflow
	// Must be done now because r could be the same as s or t
	cc_unit underflow = ccn_cmp(n, s, t) < 0;
	// Make t one's complement
	cc_unit *t_copy = malloc(ccn_sizeof_n(n));
	for (int i = 0; i < n; i++)
	{
		t_copy[i] = ~t[i];
	}

	// Add one to make it two's complement
	ccn_add1(n, t_copy, t_copy, 1);

	// Perform addition between s and the two's complement of t
	ccn_add(n, r, s, t_copy);

	free(t_copy);
	return underflow;

}

cc_unit ccn_abs(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_sub1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

/*
 * r = s + t
 */
cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
	cc_unit carry = 0;
	for (int i = 0; i < n; i++)
	{
		cc_unit s_current = s[i];
		cc_unit t_current = t[i];
		cc_unit sum = s_current + t_current + carry;
		r[i] = sum;
		// Overflow check
		if (s_current > sum - carry)
		{
			carry = 1;
		}
		else
		{
			carry = 0;
		}
	}
	return carry;
}

cc_unit ccn_add1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v)
{
	cc_size i;
	cc_unit last = s[n-1];
	const cc_unit max = CCN_UNIT_MASK;
	memcpy(r, s, ccn_sizeof_n(n));
	for (i = 0; i < n; i++)
	{
		// Handle overflow
		if (r[i] + v < r[i])
		{
			r[i] += v;
			v = 1;

		}
		else
		{
			r[i] += v;
			v = 0;
			break;
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
	printf("size: %zu\n", n);
	for (int i = 0; i < n; i++)
	{
#if CCN_UNIT_SIZE == 8
		printf("%llx\n", s[i]);
#elif CCN_UNIT_SIZE == 4
		printf("%x\n", s[i]);
#endif
	}
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
