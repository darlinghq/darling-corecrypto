#include <corecrypto/ccn.h>

/* Return the number of used units after stripping leading 0 units.  */
CC_PURE CC_NONNULL2
cc_size ccn_n(cc_size n, const cc_unit *s) {
}

/* s >> k -> r return bits shifted out of least significant word in bits [0, n>
 { N bit, scalar -> N bit } N = n * sizeof(cc_unit) * 8
 the _multi version doesn't return the shifted bits, but does support multiple
 word shifts.  */
CC_NONNULL((2, 3))
cc_unit ccn_shift_right(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
}
CC_NONNULL((2, 3))
void ccn_shift_right_multi(cc_size n, cc_unit *r,const cc_unit *s, size_t k) {
}

/* s << k -> r return bits shifted out of most significant word in bits [0, n>
 { N bit, scalar -> N bit } N = n * sizeof(cc_unit) * 8
 the _multi version doesn't return the shifted bits, but does support multiple
 word shifts */
CC_NONNULL((2, 3))
cc_unit ccn_shift_left(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
}
CC_NONNULL((2, 3))
void ccn_shift_left_multi(cc_size n, cc_unit *r, const cc_unit *s, size_t k) {
}

/* s == 0 -> return 0 | s > 0 -> return index (starting at 1) of most
 significant bit that is 1.
 { N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL2
size_t ccn_bitlen(cc_size n, const cc_unit *s) {
}

/* Returns the number of bits which are zero before the first one bit
   counting from least to most significant bit. */
CC_NONNULL2
size_t ccn_trailing_zeros(cc_size n, const cc_unit *s) {
}

/* s < t -> return - 1 | s == t -> return 0 | s > t -> return 1
 { N bit, N bit -> int } N = n * sizeof(cc_unit) * 8 */
CC_PURE CC_NONNULL((2, 3))
int ccn_cmp(cc_size n, const cc_unit *s, const cc_unit *t) {
}

/* s - t -> r return 1 iff t > s
 { N bit, N bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3, 4))
cc_unit ccn_sub(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
}

/* |s - t| -> r return 1 iff t > s, 0 otherwise */
cc_unit ccn_abs(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
}

/* s - v -> r return 1 iff v > s return 0 otherwise.
 { N bit, sizeof(cc_unit) * 8 bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3))
cc_unit ccn_sub1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v) {
}

/* s + t -> r return carry if result doesn't fit in n bits.
 { N bit, N bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3, 4))
cc_unit ccn_add(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
}

/* s + v -> r return carry if result doesn't fit in n bits.
 { N bit, sizeof(cc_unit) * 8 bit -> N bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3))
cc_unit ccn_add1(cc_size n, cc_unit *r, const cc_unit *s, cc_unit v) {
}

CC_NONNULL((2, 3, 4))
void ccn_lcm(cc_size n, cc_unit *r2n, const cc_unit *s, const cc_unit *t) {
}


/* s * t -> r_2n                   r_2n must not overlap with s nor t
 { n bit, n bit -> 2 * n bit } n = count * sizeof(cc_unit) * 8
 { N bit, N bit -> 2N bit } N = ccn_bitsof(n) */
CC_NONNULL((2, 3, 4))
void ccn_mul(cc_size n, cc_unit *r_2n, const cc_unit *s, const cc_unit *t) {
}

/* s * t -> r_2n                   r_2n must not overlap with s nor t
 { n bit, n bit -> 2 * n bit } n = count * sizeof(cc_unit) * 8
 { N bit, N bit -> 2N bit } N = ccn_bitsof(n) 
 Provide a workspace for potential speedup */
CC_NONNULL((2, 3, 4, 5))
void ccn_mul_ws(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t, cc_ws_t ws) {
}

/* s[0..n) * v -> r[0..n)+return value
 { N bit, sizeof(cc_unit) * 8 bit -> N + sizeof(cc_unit) * 8 bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3))
cc_unit ccn_mul1(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit v) {
}

/* s[0..n) * v + r[0..n) -> r[0..n)+return value
 { N bit, sizeof(cc_unit) * 8 bit -> N + sizeof(cc_unit) * 8 bit } N = n * sizeof(cc_unit) * 8 */
CC_NONNULL((2, 3))
cc_unit ccn_addmul1(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit v) {
}

/* r = gcd(s, t).
   N bit, N bit -> N bit */
CC_NONNULL((2, 3, 4))
void ccn_gcd(cc_size n, cc_unit *r, const cc_unit *s, const cc_unit *t) {
}

/* r = gcd(s, t).
 N bit, N bit -> O bit */
CC_NONNULL((2, 4, 6))
void ccn_gcdn(cc_size rn, cc_unit *r, cc_size sn, const cc_unit *s, cc_size tn, const cc_unit *t) {
}

/* r = (data, len) treated as a big endian byte array, return -1 if data
 doesn't fit in r, return 0 otherwise. */
CC_NONNULL((2, 4))
int ccn_read_uint(cc_size n, cc_unit *r, size_t data_size, const uint8_t *data) {
}

/* Return actual size in bytes needed to serialize s. */
CC_PURE CC_NONNULL2
size_t ccn_write_uint_size(cc_size n, const cc_unit *s) {
}

/* Serialize s, to out.
   First byte of byte stream is the m.s. byte of s,
   regardless of the size of cc_unit.

   No assumption is made about the alignment of out.

   The out_size argument should be the value returned from ccn_write_uint_size,
   and is also the exact number of bytes this function will write to out.
   If out_size if less than the value returned by ccn_write_uint_size, only the
   first out_size non-zero most significant octets of s will be written. */
CC_NONNULL((2, 4))
void ccn_write_uint(cc_size n, const cc_unit *s, size_t out_size, void *out) {
}

/*  Return actual size in bytes needed to serialize s as int 
    (adding leading zero if high bit is set). */
CC_PURE CC_NONNULL2
size_t ccn_write_int_size(cc_size n, const cc_unit *s) {
}

/*  Serialize s, to out.
    First byte of byte stream is the m.s. byte of s,
    regardless of the size of cc_unit.

    No assumption is made about the alignment of out.

    The out_size argument should be the value returned from ccn_write_int_size,
    and is also the exact number of bytes this function will write to out.
    If out_size if less than the value returned by ccn_write_int_size, only the
    first out_size non-zero most significant octets of s will be written. */
CC_NONNULL((2, 4))
void ccn_write_int(cc_size n, const cc_unit *s, size_t out_size, void *out) {
}

/* s -> r
 { n bit -> n bit } */
CC_NONNULL((2, 3))
void ccn_set(cc_size n, cc_unit *r, const cc_unit *s) {
}

CC_NONNULL2
void ccn_zero_multi(cc_size n, cc_unit *r, ...) {
}

CC_NONNULL2
void ccn_print(cc_size n, const cc_unit *s) {
}

CC_NONNULL3
void ccn_lprint(cc_size n, const char *label, const cc_unit *s) {
}

/* Make a ccn of size ccn_nof(nbits) units with up to nbits sized random value. */
CC_NONNULL((2, 3))
int ccn_random_bits(cc_size nbits, cc_unit *r, struct ccrng_state *rng) {
}

/*!
 @brief ccn_make_recip(cc_size nd, cc_unit *recip, const cc_unit *d) computes the reciprocal of d: recip = 2^2b/d where b=bitlen(d)

 @param nd      length of array d
 @param recip   returned reciprocal of size nd+1
 @param d       input number d
*/
CC_NONNULL((2, 3))
void ccn_make_recip(cc_size nd, cc_unit *recip, const cc_unit *d) {
}

CC_NONNULL((6, 8))
int ccn_div_euclid(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d) {
}

CC_NONNULL((6, 8, 9))
int ccn_div_use_recip(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d, const cc_unit *recip_d) {
}
