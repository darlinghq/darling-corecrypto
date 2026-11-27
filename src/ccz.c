#include <corecrypto/ccz.h>
#include <corecrypto/cc.h>
#include <corecrypto/private/dbn.h>
#include <stdio.h>
#include <string.h>

/*
 * Arbitrary-size integers on top of ccn.
 *
 * Representation used here: u[0..n-1] holds the magnitude with no leading
 * zero unit (n == 0 for zero); |sac| is the number of units allocated at u,
 * and sac < 0 marks a negative value. Memory comes from the ccz_class.
 *
 * Division truncates toward zero (the remainder takes the dividend's sign);
 * ccz_mod and the modular functions return values in [0, |modulus|).
 * Only ccz_expmod is constant time (in the base and exponent values, for
 * given lengths); the other functions are general purpose arithmetic.
 */

#if CCN_UNIT_SIZE == 8
typedef unsigned __int128 zwide;
#else
typedef uint64_t zwide;
#endif

#define UNIT_BITS ((size_t)CCN_UNIT_BITS)

static cc_size zcap(const ccz *z)
{
	return (cc_size)(z->sac < 0 ? -z->sac : z->sac);
}

static int zneg(const ccz *z)
{
	return z->sac < 0;
}

static void zsign(ccz *z, int negative)
{
	int c = (int)zcap(z);
	z->sac = (negative && z->n) ? -c : c;
}

static cc_size zlength(cc_size n, const cc_unit *u)
{
	while (n > 0 && u[n - 1] == 0)
		n--;
	return n;
}

static cc_unit *zalloc(const ccz *z, cc_size units)
{
	if (units == 0)
		units = 1;
	cc_unit *p = z->isa->ccz_alloc(z->isa->ctx, ccn_sizeof_n(units));
	if (p)
		memset(p, 0, ccn_sizeof_n(units));
	return p;
}

static void zrelease(const ccz *z, cc_size units, cc_unit *p)
{
	if (!p)
		return;
	if (units == 0)
		units = 1;
	cc_clear(ccn_sizeof_n(units), p);
	z->isa->ccz_free(z->isa->ctx, ccn_sizeof_n(units), p);
}

/* replace r's storage with buf (units allocated) holding a magnitude */
static void zadopt(ccz *r, cc_unit *buf, cc_size units, int negative)
{
	if (units == 0)
		units = 1;
	if (zcap(r))
		zrelease(r, zcap(r), r->u);
	r->u = buf;
	r->n = zlength(units, buf);
	r->sac = (int)units;
	zsign(r, negative);
}

static int zreserve(ccz *r, cc_size units)
{
	cc_size have = zcap(r);
	if (units <= have)
		return 0;
	cc_unit *p = zalloc(r, units);
	if (!p)
		return -1;
	int negative = zneg(r);
	if (r->n)
		memcpy(p, r->u, ccn_sizeof_n(r->n));
	cc_size n = r->n;
	zadopt(r, p, units, 0);
	r->n = n;
	zsign(r, negative);
	return 0;
}

static int mag_cmp(cc_size an, const cc_unit *a, cc_size bn, const cc_unit *b)
{
	if (an != bn)
		return an < bn ? -1 : 1;
	for (cc_size i = an; i > 0; i--) {
		if (a[i - 1] != b[i - 1])
			return a[i - 1] < b[i - 1] ? -1 : 1;
	}
	return 0;
}

/* buf (units) += x (xn <= units) */
static void mag_add_into(cc_size units, cc_unit *buf, cc_size xn, const cc_unit *x)
{
	cc_unit carry = 0;
	for (cc_size i = 0; i < units; i++) {
		zwide sum = (zwide)buf[i] + (i < xn ? x[i] : 0) + carry;
		buf[i] = (cc_unit)sum;
		carry = (cc_unit)(sum >> UNIT_BITS);
	}
}

/* buf (units) -= x, for buf >= x */
static void mag_sub_from(cc_size units, cc_unit *buf, cc_size xn, const cc_unit *x)
{
	cc_unit borrow = 0;
	for (cc_size i = 0; i < units; i++) {
		zwide diff = (zwide)buf[i] - (i < xn ? x[i] : 0) - borrow;
		buf[i] = (cc_unit)diff;
		borrow = (cc_unit)(diff >> UNIT_BITS) & 1;
	}
}

/* buf = buf * m + a, returns the carry out */
static cc_unit mag_mul_add_small(cc_size units, cc_unit *buf, cc_unit m, cc_unit a)
{
	cc_unit carry = a;
	for (cc_size i = 0; i < units; i++) {
		zwide acc = (zwide)buf[i] * m + carry;
		buf[i] = (cc_unit)acc;
		carry = (cc_unit)(acc >> UNIT_BITS);
	}
	return carry;
}

/* buf = buf / d, returns the remainder */
static cc_unit mag_div_small(cc_size units, cc_unit *buf, cc_unit d)
{
	zwide rem = 0;
	for (cc_size i = units; i > 0; i--) {
		zwide cur = (rem << UNIT_BITS) | buf[i - 1];
		buf[i - 1] = (cc_unit)(cur / d);
		rem = cur % d;
	}
	return (cc_unit)rem;
}

/* a ccz on the stack holding a small value */
#define SMALL_CCZ(name, cls, value) \
	cc_unit name##_unit = (cc_unit)(value); \
	ccz name = { .n = (value) ? 1 : 0, .isa = (cls), .sac = 1, .u = &name##_unit }

size_t ccz_size(struct ccz_class *cls)
{
	(void)cls;
	return sizeof(struct ccz);
}

void ccz_init(struct ccz_class *cls, ccz *r)
{
	r->n = 0;
	r->isa = cls;
	r->sac = 0;
	r->u = NULL;
}

void ccz_free(ccz *r)
{
	if (zcap(r))
		zrelease(r, zcap(r), r->u);
	r->n = 0;
	r->sac = 0;
	r->u = NULL;
}

void ccz_zero(ccz *r)
{
	if (zcap(r))
		cc_clear(ccn_sizeof_n(zcap(r)), r->u);
	r->n = 0;
	zsign(r, 0);
}

void ccz_set(ccz *r, const ccz *s)
{
	if (r == s)
		return;
	if (zreserve(r, s->n))
		return;
	if (zcap(r))
		cc_clear(ccn_sizeof_n(zcap(r)), r->u);
	if (s->n)
		memcpy(r->u, s->u, ccn_sizeof_n(s->n));
	r->n = s->n;
	zsign(r, zneg(s));
}

void ccz_seti(ccz *r, uint64_t v)
{
	const cc_size units = sizeof(v) / CCN_UNIT_SIZE;
	if (zreserve(r, units))
		return;
	cc_clear(ccn_sizeof_n(zcap(r)), r->u);
	for (cc_size i = 0; i < units; i++)
		r->u[i] = (cc_unit)(v >> (i * UNIT_BITS));
	r->n = zlength(units, r->u);
	zsign(r, 0);
}

size_t ccz_bitlen(const ccz *s)
{
	if (s->n == 0)
		return 0;
	size_t bits = (s->n - 1) * UNIT_BITS;
	for (cc_unit top = s->u[s->n - 1]; top; top >>= 1)
		bits++;
	return bits;
}

size_t ccz_trailing_zeros(const ccz *s)
{
	for (cc_size i = 0; i < s->n; i++) {
		if (s->u[i])
			return i * UNIT_BITS + (size_t)__builtin_ctzll((unsigned long long)s->u[i]);
	}
	return 0;
}

size_t ccz_write_uint_size(const ccz *s)
{
	return (ccz_bitlen(s) + 7) / 8;
}

void ccz_mulmod(ccz *r, const ccz *s, const ccz *t, const ccz *u)
{
	ccz product;
	ccz_init(r->isa, &product);
	ccz_mul(&product, s, t);
	ccz_mod(r, &product, u);
	ccz_free(&product);
}

void ccz_sqrmod(ccz *r, const ccz *s, const ccz *t)
{
	ccz_mulmod(r, s, s, t);
}

/*
 * r = s^t mod |u|, in [0, |u|). u == 0 or a negative exponent (which would
 * need a modular inverse) give 0; t == 0 gives 1 mod |u|.
 */
void ccz_expmod(ccz *r, const ccz *s, const ccz *t, const ccz *u)
{
	const cc_size n = u->n;

	if (n == 0 || (zneg(t) && t->n)) {
		ccz_zero(r);
		return;
	}

	ccz base;
	ccz_init(r->isa, &base);
	ccz_mod(&base, s, u); /* below |u|, so at most n units */

	cc_unit *b = zalloc(r, n);
	cc_unit *result = zalloc(r, n);
	if (!b || !result) {
		zrelease(r, n, b);
		zrelease(r, n, result);
		ccz_free(&base);
		return;
	}
	if (base.n)
		memcpy(b, base.u, ccn_sizeof_n(base.n));
	ccz_free(&base);

	/* u may be r, so it is read before r is replaced */
	if (dbn_modexp(n, result, b, t->n, t->u, u->u)) {
		zrelease(r, n, b);
		zrelease(r, n, result);
		return;
	}
	zrelease(r, n, b);
	zadopt(r, result, n, 0);
}

bool ccz_bit(const ccz *s, size_t k)
{
	if (k / UNIT_BITS >= s->n)
		return false;
	return (s->u[k / UNIT_BITS] >> (k % UNIT_BITS)) & 1;
}

void ccz_set_bit(ccz *r, size_t k, bool value)
{
	const cc_size unit = k / UNIT_BITS;
	if (value) {
		if (zreserve(r, unit + 1))
			return;
		r->u[unit] |= (cc_unit)1 << (k % UNIT_BITS);
		if (r->n < unit + 1)
			r->n = unit + 1;
	} else if (unit < r->n) {
		r->u[unit] &= ~((cc_unit)1 << (k % UNIT_BITS));
		int negative = zneg(r);
		r->n = zlength(r->n, r->u);
		zsign(r, negative);
	}
}

void ccz_write_uint(const ccz *s, size_t out_size, void *out)
{
	ccn_write_uint(s->n, s->u, out_size, out);
}

/* as ccn_write_int_size: a leading zero byte when the top bit of the top byte is set */
size_t ccz_write_int_size(const ccz *s)
{
	size_t bits = ccz_bitlen(s);
	return (bits + 7) / 8 + (bits % 8 == 0);
}

void ccz_write_int(const ccz *s, size_t out_size, void *out)
{
	ccn_write_uint(s->n, s->u, out_size, out);
}

static const char radix_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

size_t ccz_write_radix_size(const ccz *s, unsigned radix)
{
	if (radix < 2 || radix > 36)
		return 0;
	if (s->n == 0)
		return 1;

	cc_unit *work = zalloc(s, s->n);
	if (!work)
		return 0;
	memcpy(work, s->u, ccn_sizeof_n(s->n));

	size_t digits = 0;
	for (cc_size len = s->n; len; len = zlength(len, work)) {
		mag_div_small(len, work, radix);
		digits++;
	}
	zrelease(s, s->n, work);
	return digits + (zneg(s) ? 1 : 0);
}

/* the digits right-aligned in out, '0'-filled on the left, '-' first if negative */
void ccz_write_radix(const ccz *s, size_t out_size, void *out, unsigned radix)
{
	char *text = out;
	memset(text, '0', out_size);
	if (radix < 2 || radix > 36 || s->n == 0)
		return;

	cc_unit *work = zalloc(s, s->n);
	if (!work)
		return;
	memcpy(work, s->u, ccn_sizeof_n(s->n));

	size_t pos = out_size;
	for (cc_size len = s->n; len && pos > 0; len = zlength(len, work))
		text[--pos] = radix_digits[mag_div_small(len, work, radix)];
	zrelease(s, s->n, work);

	if (zneg(s) && out_size > 0)
		text[0] = '-';
}

void ccz_read_uint(ccz *r, size_t data_size, const uint8_t *data)
{
	while (data_size > 0 && *data == 0) {
		data++;
		data_size--;
	}
	const cc_size units = ccn_nof_size(data_size);
	cc_unit *buf = zalloc(r, units);
	if (!buf)
		return;
	if (data_size)
		ccn_read_uint(units, buf, data_size, data);
	zadopt(r, buf, units, 0);
}

/* the bytes are read as an unsigned magnitude, as ccz_write_int writes it */
void ccz_read_int(ccz *r, size_t data_size, const uint8_t *data)
{
	ccz_read_uint(r, data_size, data);
}

int ccz_read_radix(ccz *r, size_t data_size, const char *data, unsigned radix)
{
	if (radix < 2 || radix > 36)
		return CCZ_INVALID_RADIX_ERROR;

	int negative = 0;
	if (data_size > 0 && data[0] == '-') {
		negative = 1;
		data++;
		data_size--;
	}

	/* each digit adds at most 6 bits */
	const cc_size units = ccn_nof(data_size * 6) + 1;
	cc_unit *buf = zalloc(r, units);
	if (!buf)
		return CCZ_INVALID_INPUT_ERROR;

	for (size_t i = 0; i < data_size; i++) {
		char c = data[i];
		unsigned digit;
		if (c >= '0' && c <= '9')
			digit = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'z')
			digit = (unsigned)(c - 'a') + 10;
		else if (c >= 'A' && c <= 'Z')
			digit = (unsigned)(c - 'A') + 10;
		else
			digit = 36;
		if (digit >= radix) {
			zrelease(r, units, buf);
			return CCZ_INVALID_INPUT_ERROR;
		}
		mag_mul_add_small(units, buf, radix, digit);
	}

	zadopt(r, buf, units, negative);
	return 0;
}

int ccz_cmp(const ccz *s, const ccz *t)
{
	int sn = zneg(s), tn = zneg(t);
	if (sn != tn)
		return sn ? -1 : 1;
	int c = mag_cmp(s->n, s->u, t->n, t->u);
	return sn ? -c : c;
}

int ccz_cmpi(const ccz *s, uint32_t v)
{
	SMALL_CCZ(small, s->isa, v);
	return ccz_cmp(s, &small);
}

void ccz_neg(ccz *r)
{
	zsign(r, !zneg(r));
}

/* r = s + t, or s - t when subtract is set */
static void zadd_signed(ccz *r, const ccz *s, const ccz *t, int subtract)
{
	const int sn = zneg(s);
	const int tn = zneg(t) ^ (subtract && t->n);
	const cc_size units = (s->n > t->n ? s->n : t->n) + 1;
	cc_unit *buf = zalloc(r, units);
	int negative;

	if (!buf)
		return;
	if (sn == tn) {
		if (s->n)
			memcpy(buf, s->u, ccn_sizeof_n(s->n));
		mag_add_into(units, buf, t->n, t->u);
		negative = sn;
	} else if (mag_cmp(s->n, s->u, t->n, t->u) >= 0) {
		if (s->n)
			memcpy(buf, s->u, ccn_sizeof_n(s->n));
		mag_sub_from(units, buf, t->n, t->u);
		negative = sn;
	} else {
		memcpy(buf, t->u, ccn_sizeof_n(t->n));
		mag_sub_from(units, buf, s->n, s->u);
		negative = tn;
	}
	zadopt(r, buf, units, negative);
}

void ccz_add(ccz *r, const ccz *s, const ccz *t)
{
	zadd_signed(r, s, t, 0);
}

void ccz_addi(ccz *r, const ccz *s, uint32_t v)
{
	SMALL_CCZ(small, s->isa, v);
	zadd_signed(r, s, &small, 0);
}

void ccz_sub(ccz *r, const ccz *s, const ccz *t)
{
	zadd_signed(r, s, t, 1);
}

void ccz_subi(ccz *r, const ccz *s, uint32_t v)
{
	SMALL_CCZ(small, s->isa, v);
	zadd_signed(r, s, &small, 1);
}

void ccz_mul(ccz *r, const ccz *s, const ccz *t)
{
	const cc_size units = s->n + t->n;
	cc_unit *buf = zalloc(r, units);
	if (!buf)
		return;
	for (cc_size i = 0; i < t->n; i++) {
		cc_unit carry = 0;
		for (cc_size j = 0; j < s->n; j++) {
			zwide acc = (zwide)s->u[j] * t->u[i] + buf[i + j] + carry;
			buf[i + j] = (cc_unit)acc;
			carry = (cc_unit)(acc >> UNIT_BITS);
		}
		buf[i + s->n] = carry;
	}
	zadopt(r, buf, units, zneg(s) ^ zneg(t));
}

void ccz_muli(ccz *r, const ccz *s, uint32_t v)
{
	SMALL_CCZ(small, s->isa, v);
	ccz_mul(r, s, &small);
}

void ccz_sqr(ccz *r, const ccz *s)
{
	ccz_mul(r, s, s);
}

/* q = s / t truncated toward zero, r = s - q * t; either may be NULL. t == 0 gives 0, 0. */
void ccz_divmod(ccz *q, ccz *r, const ccz *s, const ccz *t)
{
	const ccz *any = q ? q : r;
	if (!any)
		return;
	if (t->n == 0 || s->n == 0) {
		if (q)
			ccz_zero(q);
		if (r)
			ccz_zero(r);
		return;
	}

	cc_unit *qbuf = zalloc(any, s->n);
	cc_unit *rbuf = zalloc(any, t->n);
	if (!qbuf || !rbuf) {
		zrelease(any, s->n, qbuf);
		zrelease(any, t->n, rbuf);
		return;
	}
	const cc_size sn = s->n, tn = t->n;
	const int s_negative = zneg(s), t_negative = zneg(t);
	dbn_divrem(sn, qbuf, tn, rbuf, s->u, t->u);

	if (q)
		zadopt(q, qbuf, sn, s_negative ^ t_negative);
	else
		zrelease(any, sn, qbuf);
	if (r)
		zadopt(r, rbuf, tn, s_negative);
	else
		zrelease(any, tn, rbuf);
}

/* r = s >> k on the magnitude */
void ccz_lsr(ccz *r, const ccz *s, size_t k)
{
	const cc_size skip = k / UNIT_BITS;
	const size_t bits = k % UNIT_BITS;
	if (skip >= s->n) {
		ccz_zero(r);
		return;
	}
	const cc_size units = s->n - skip;
	cc_unit *buf = zalloc(r, units);
	if (!buf)
		return;
	for (cc_size i = 0; i < units; i++) {
		cc_unit lo = s->u[i + skip] >> bits;
		cc_unit hi = (bits && i + skip + 1 < s->n) ? s->u[i + skip + 1] << (UNIT_BITS - bits) : 0;
		buf[i] = lo | hi;
	}
	zadopt(r, buf, units, zneg(s));
}

/* r = s << k on the magnitude */
void ccz_lsl(ccz *r, const ccz *s, size_t k)
{
	if (s->n == 0) {
		ccz_zero(r);
		return;
	}
	const cc_size skip = k / UNIT_BITS;
	const size_t bits = k % UNIT_BITS;
	const cc_size units = s->n + skip + 1;
	cc_unit *buf = zalloc(r, units);
	if (!buf)
		return;
	for (cc_size i = 0; i < s->n; i++) {
		buf[i + skip] |= s->u[i] << bits;
		if (bits)
			buf[i + skip + 1] = s->u[i] >> (UNIT_BITS - bits);
	}
	zadopt(r, buf, units, zneg(s));
}

/* r = s mod |t| in [0, |t|); t == 0 gives 0 */
void ccz_mod(ccz *r, const ccz *s, const ccz *t)
{
	if (t->n == 0 || s->n == 0) {
		ccz_zero(r);
		return;
	}
	const cc_size tn = t->n;
	cc_unit *rbuf = zalloc(r, tn);
	if (!rbuf)
		return;
	dbn_divrem(s->n, NULL, tn, rbuf, s->u, t->u);
	if (zneg(s) && !dbn_is_zero(tn, rbuf)) {
		/* -a mod m = m - (a mod m) */
		cc_unit *flipped = zalloc(r, tn);
		if (!flipped) {
			zrelease(r, tn, rbuf);
			return;
		}
		dbn_sub(tn, flipped, t->u, rbuf);
		zrelease(r, tn, rbuf);
		rbuf = flipped;
	}
	zadopt(r, rbuf, tn, 0);
}

bool ccz_is_zero(const ccz *s)
{
	return s->n == 0;
}

bool ccz_is_one(const ccz *s)
{
	return s->n == 1 && s->u[0] == 1 && !zneg(s);
}

bool ccz_is_negative(const ccz *s)
{
	return zneg(s);
}

int ccz_random_bits(ccz *r, size_t nbits, struct ccrng_state *rng)
{
	const cc_size units = ccn_nof(nbits);
	if (units == 0) {
		ccz_zero(r);
		return 0;
	}
	cc_unit *buf = zalloc(r, units);
	if (!buf)
		return -1;
	int result = ccn_random_bits(nbits, buf, rng);
	if (result) {
		zrelease(r, units, buf);
		return result;
	}
	zadopt(r, buf, units, 0);
	return 0;
}

/* not implemented yet */

void ccz_gcd(ccz *r, const ccz *s, const ccz *t)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccz_lcm(ccz *r, const ccz *s, const ccz *t)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

int ccz_invmod(ccz *r, const ccz *s, const ccz *t)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return -1;
}

bool ccz_is_prime(const ccz *s, unsigned depth)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccz_print(const ccz *s)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

void ccz_lprint(const char *label, const ccz *s)
{
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

