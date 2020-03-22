#include <corecrypto/ccn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

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
cc_unit ccn_shift_right(cc_size n, cc_unit* r, const cc_unit* s, size_t k) {
  cc_unit carry = 0;
  cc_unit temp;

  for (cc_size i = n; i > 0; --i) {
    temp = s[i - 1];
    r[i - 1] = temp >> k;
    r[i - 1] |= carry;
    carry = temp << (CCN_UNIT_BITS - k);
  }

  return carry;
}
void ccn_shift_right_multi(cc_size n, cc_unit* r, const cc_unit* s, size_t k) {
	cc_size discarded_units = k / CCN_UNIT_BITS;
	k -= discarded_units * CCN_UNIT_BITS;
	cc_unit carry = 0;
	cc_unit temp;

	for (cc_size i = n; i > discarded_units; --i) {
		temp = s[i - 1];
		r[(i - 1) - discarded_units] = temp >> k;
		r[(i - 1) - discarded_units] |= carry;
		if (i > n - discarded_units)
			r[i - 1] = 0;
		carry = temp << (CCN_UNIT_BITS - k);
	}
}

/*
 * k must be <= CCN_UNIT_BITS
 *
 * r and s may be equal
 */
cc_unit ccn_shift_left(cc_size n, cc_unit* r, const cc_unit* s, size_t k) {
  cc_unit carry = 0;
  cc_unit temp;

  for (cc_size i = 0; i < n; ++i) {
    temp = s[i];
    r[i] = temp << k;
    r[i] |= carry;
    carry = temp >> (CCN_UNIT_BITS - k);
  }

  return carry;
}

void ccn_shift_left_multi(cc_size n, cc_unit* r, const cc_unit* s, size_t k) {
	cc_size discarded_units = k / CCN_UNIT_BITS;
	k -= discarded_units * CCN_UNIT_BITS;
	cc_unit carry = 0;
	cc_unit temp;

	for (cc_size i = 0; i < n - discarded_units; ++i) {
		temp = s[i];
		r[i + discarded_units] = temp << k;
		r[i + discarded_units] |= carry;
		if (i < discarded_units)
			r[i] = 0;
		carry = temp >> (CCN_UNIT_BITS - k);
	}
}

size_t ccn_bitlen(cc_size n, const cc_unit *s) {
  cc_size used = ccn_n(n, s);

  // no units used == no bits used
  if (used == 0)
    return 0;

  cc_unit last_used_unit = s[used - 1];

  // if used unit == 0, return 1
  //
  // this check is necessary because `__builtin_clzl` performs
  // undefined behavior when the argument given is 0
  if (used == 1 && last_used_unit == 0)
    return 1;

  // CLZ counts the number of leading zero bits in the
  // the last unit that we know not to be all zeroes.
  return used * CCN_UNIT_BITS - __builtin_clzl(last_used_unit);
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
int ccn_cmp(cc_size n, const cc_unit* s, const cc_unit* t) {
  for (cc_size i = n; i > 0; --i) {
    if (s[i - 1] < t[i - 1]) {
      return -1;
    } else if (s[i - 1] > t[i - 1]) {
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
  cc_unit *t_copy = __builtin_alloca(ccn_sizeof_n(n));
  for (cc_size i = 0; i < n; ++i)
    t_copy[i] = ~t[i];

  // Add one to make it two's complement
  ccn_add1(n, t_copy, t_copy, 1);

  // Perform addition between s and the two's complement of t
  ccn_add(n, r, s, t_copy);

  return underflow;
}

cc_unit ccn_abs(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
  printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

cc_unit ccn_sub1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v) {
  ccn_add1(n, r, s, -1 * v);
  return n < 1 || ((n == 1) && s[0] < v);
}

/*
 * r = s + t
 */
cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
  cc_unit carry = 0;
  for (cc_size i = 0; i < n; ++i) {
    cc_unit s_current = s[i];
    cc_unit t_current = t[i];
    cc_unit sum = s_current + t_current + carry;
    r[i] = sum;
    // Overflow check
    if (s_current > sum || t_current > sum) {
      carry = 1;
    } else {
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

#define CC_HI_BITS(x) (x >> (CCN_UNIT_BITS >> 1))
#define CC_LO_BITS(x) (x & (CCN_UNIT_MASK >> (CCN_UNIT_BITS >> 1)))
#define CC_COMBINE(lo, hi) ((hi << (CCN_UNIT_BITS >> 1)) | lo)

void ccn_mul(cc_size n, cc_unit *r_2n, const cc_unit *s, const cc_unit *t) {
  // we're using the karatsuba algorithm in base 2^64
  // in the following pseudocode, B is the base of the numbers
  /*
    procedure karatsuba(num1, num2)
      if (num1 < B) and (num2 < B)
          return num1 * num2

      // Calculates the size of the numbers.
      m = max(size_base(num1, B), size_base(num2, B))
      m2 = floor(m / 2)

      // Split the digit sequences in the middle.
      high1, low1 = split_at(num1, m2)
      high2, low2 = split_at(num2, m2)

      // 3 calls made to numbers approximately half the size.
      z0 = karatsuba(low1, low2)
      z1 = karatsuba(high1, high2)
      z2 = karatsuba((low1 + high1), (low2 + high2))

      t0 = (z2 - z0 - z1) * (B ** m2)
      t1 = z1 * (B ** (m2 * 2))
      // this is equivalent to:
      // t0 = (z2 - z0 - z1) << m2
      // t1 = z1 << (m2 * 2)

      return t0 + t1 + z0
  */
  cc_size s_n = ccn_n(n, s);
  cc_size t_n = ccn_n(n, t);

  memset(r_2n, 0, ccn_sizeof_n(n * 2));

  if (s_n < 2 && t_n < 2) {
    // multiplication algorithm that prevents overflow
    // based on https://stackoverflow.com/a/1815371
    const cc_unit s_hi = CC_HI_BITS(s[0]);
    const cc_unit s_lo = CC_LO_BITS(s[0]);
    const cc_unit t_hi = CC_HI_BITS(t[0]);
    const cc_unit t_lo = CC_LO_BITS(t[0]);

    cc_unit x = s_lo * t_lo;
    const cc_unit prod_0 = CC_LO_BITS(x);

    x = s_hi * t_lo + CC_HI_BITS(x);
    cc_unit prod_1 = CC_LO_BITS(x);
    cc_unit prod_2 = CC_HI_BITS(x);

    x = prod_1 + s_lo * t_hi;
    prod_1 = CC_LO_BITS(x);

    x = prod_2 + s_hi * t_hi + CC_HI_BITS(x);

    r_2n[0] = CC_COMBINE(prod_0, prod_1);
    r_2n[1] = x;

    return;
  }

  cc_size max_n = s_n > t_n ? s_n : t_n;
  cc_size half_n = (max_n + 1) / 2;
  cc_size result_n = max_n * 2;
  cc_size intermediate_mul_n = (half_n * 2) + 2;

  cc_size max_size = ccn_sizeof_n(max_n);
  cc_size half_size = ccn_sizeof_n(half_n);
  cc_size half_size_for_addition = ccn_sizeof_n(half_n + 1);
  cc_size result_size = ccn_sizeof_n(result_n);
  cc_size intermediate_mul_size = ccn_sizeof_n(intermediate_mul_n);
  cc_size hi_half_size = max_size - half_size;

  // half_size_for_addition is used to allocate enough for addition
  // later when we do `hi + lo -> lo`

  cc_unit* s_hi = __builtin_alloca(half_size);
  cc_unit* s_lo = __builtin_alloca(half_size_for_addition);

  cc_unit* t_hi = __builtin_alloca(half_size);
  cc_unit* t_lo = __builtin_alloca(half_size_for_addition);

  memset(s_hi, 0, half_size);
  memset(s_lo, 0, half_size_for_addition);
  memset(t_hi, 0, half_size);
  memset(t_lo, 0, half_size_for_addition);

  // copy `half_size` bytes from `s` into `s_lo`
  memcpy(s_lo, s, half_size);
  // copy the rest into `s_hi`
  memcpy(s_hi, (uint8_t*)s + half_size, hi_half_size);

  // copy `half_size` bytes from `t` into `t_lo`
  memcpy(t_lo, t, half_size);
  // copy the rest into `t_hi`
  memcpy(t_hi, (uint8_t*)t + half_size, hi_half_size);

  cc_unit* z0 = __builtin_alloca(intermediate_mul_size);
  cc_unit* z1 = __builtin_alloca(intermediate_mul_size);
  cc_unit* z2 = __builtin_alloca(intermediate_mul_size);

  memset(z0, 0, intermediate_mul_size);
  memset(z1, 0, intermediate_mul_size);
  memset(z2, 0, intermediate_mul_size);

  // z0 = s_lo * t_lo
  ccn_mul(half_n, z0, s_lo, t_lo);
  // z1 = s_hi * t_hi
  ccn_mul(half_n, z1, s_hi, t_hi);

  // we add the `hi`s directly into the `lo`s to avoid additional allocations

  // s_lo = s_lo + s_hi
  cc_unit s_carry = ccn_add(half_n, s_lo, s_lo, s_hi);
  // t_lo = t_lo + s_hi
  cc_unit t_carry = ccn_add(half_n, t_lo, t_lo, t_hi);

  // this is safe; remember we already allocated an extra unit in the `lo`s
  s_lo[half_n] = s_carry;
  t_lo[half_n] = t_carry;

  // z2 = (s_lo + s_hi) * (t_lo + t_hi)
  ccn_mul(half_n + 1, z2, s_lo, t_lo);

  cc_unit* t0 = __builtin_alloca(result_size);
  cc_unit* t1 = __builtin_alloca(result_size);

  memset(t0, 0, result_size);
  memset(t1, 0, result_size);

  // since we don't use z2 anymore, we can just subtract z1 and z0
  // directly into it to avoid additional allocations

  // z2 = z2 - z1
  ccn_sub(intermediate_mul_n, z2, z2, z1);
  // z2 = z2 - z0
  ccn_sub(intermediate_mul_n, z2, z2, z0);

  // t0 = z2 - z1 - z0
  // technically, this is `t0 = z2` because we already subtracted them into z2
  ccn_set(intermediate_mul_n, t0, z2);
  // t0 = z1
  ccn_set(intermediate_mul_n, t1, z1);

  const cc_unit* t0_end = t0 + result_n;
  const cc_unit* t1_end = t1 + result_n;

  // t0 = t0 << half_n
  //
  // shift t0 to the left by `half_n` units
  // (which in little endian is actually shifting the bytes right)
  //
  // why don't we use `ccn_shift_left`? remember that we're in base 2^64
  // `ccn_shift_left` shifts base-2 bits, not base-2^64 bits (i.e. units)
  for (cc_size i = intermediate_mul_n; i > 0; --i) {
    cc_unit* tgt = t0 + half_n + (i - 1);
    // make sure that the target isn't past our boundary
    if (tgt < t0_end)
      *tgt = t0[i - 1];
  }
  // zero the previously occupied bytes
  for (cc_size i = 0; i < half_n; ++i)
    t0[i] = 0;

  // t1 = t1 << (half_n * 2)
  //
  // shift t1 to the left by `half_n * 2` units
  for (cc_size i = intermediate_mul_n; i > 0; --i) {
    cc_unit* tgt = t1 + (half_n * 2) + (i - 1);
    // make sure that the target isn't past our boundary
    if (tgt < t1_end)
      *tgt = t1[i - 1];
  }
  // zero the previously occupied bytes
  for (cc_size i = 0; i < half_n * 2; ++i)
    t1[i] = 0;

  // r_2n = z0 + t0 + t1
  ccn_set(intermediate_mul_n, r_2n, z0);
  ccn_add(result_n, r_2n, r_2n, t0);
  ccn_add(result_n, r_2n, r_2n, t1);
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
        for (cc_size i = 0; i < CCN_UNIT_SIZE && ind >= 0; i++, ind--) {
            cc_unit c = data[ind];
            *r |= c << (i * 8);
        }
    }

    return 0;

}

size_t ccn_write_uint_size(cc_size n, const cc_unit *s) {
  n = ccn_n(n, s);
  return ccn_sizeof_n(n + 1);
};

void ccn_write_uint(cc_size n, const cc_unit *s, size_t out_size, void *out) {
	uint8_t* data = out;

	memset(data, 0, out_size);

	// CCNs are little endian, and C's bitwise operators are too.
	// thus, to write the output in big endian, we loop over the cc_units
	// backwards, and then over each octet backwards

	size_t data_idx = 0;
	for (size_t ccn_idx = n; ccn_idx > 0; --ccn_idx)
		for (uint8_t octet = CCN_UNIT_SIZE; octet > 0; --octet, ++data_idx)
			data[data_idx] = (s[ccn_idx - 1] >> ((octet - 1) * 8)) & 0xff;
}

size_t ccn_write_int_size(cc_size n, const cc_unit *s) {
  n = ccn_n(n, s);
  return ccn_sizeof_n(n);
};

void ccn_write_int(cc_size n, const cc_unit *s, size_t out_size, void *out) {
  printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccn_set(cc_size n, cc_unit *r, const cc_unit *s) {
  for (size_t i = 0; i < n; ++i) {
    r[i] = s[i];
  }
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
	// NOTE(@facekapow):
	// i actually haven't tested this implementation

	na = ccn_n(na, a);
	nd = ccn_n(nd, d);

	if (!q)
		nq = na;
	if (!r)
		nr = nd;

	if (nq < na)
		return -1;
	if (nr < nd)
		return -1;

	if (na < nd) {
		if (r)
			ccn_set(na, r, a);
		if (q)
			ccn_zero(nq, q);
		return 0;
	}

	cc_unit* tmp_d = __builtin_alloca(ccn_sizeof_n(na));
	memset(tmp_d, 0, ccn_sizeof_n(na));
	ccn_set(nd, tmp_d, d);

	// if the divisor is greater, we cannot divide!
	if (ccn_cmp(na, a, tmp_d) < 0) {
		// note that here it is ok to copy a into r
		// even though r's size depends on that of d
		// because we've determined that d is bigger than a
		if (r)
			ccn_set(na, r, a);
		if (q)
			ccn_zero(nq, q);
		return 0;
	}

	cc_unit* tmp_remainder = __builtin_alloca(ccn_sizeof_n(na));

	ccn_set(na, tmp_remainder, a);

	// we do ccn_n on every loop because ccn_cmpn looks at both n's and says one value is greater
	// than the other just based on the n's. therefore, if we want to check for real whether the
	// remainder is greater than the divisor, we need to check how many n's are actually used
	while (ccn_cmp(na, tmp_remainder, tmp_d) >= 0) {
		ccn_sub(na, tmp_remainder, tmp_remainder, tmp_d);
		if (q)
			ccn_add1(nq, q, q, 1);
	}

	// by this point, tmp_remainder should be smaller than the divisor
	// so it should be ok to copy it into the remainder (which is <= the size of the divisor)
	if (r)
		ccn_set(nr, r, tmp_remainder);

	return 0;
}

int ccn_div_use_recip(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d, const cc_unit *recip_d) {
  printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
