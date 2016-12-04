#ifndef _CORECRYPTO_CCZP_H_
#define _CORECRYPTO_CCZP_H_

#include <corecrypto/ccn.h>
#include <corecrypto/ccrng.h>

struct cczp {
    cc_size n;
    cc_unit options;
    void(*mod_prime)(const struct cczp *zp, cc_unit *r, const cc_unit *s, cc_ws_t ws);
} __attribute__((aligned(CCN_UNIT_SIZE)));

struct cczp_short {
    cc_size n;
    cc_unit options;
    void(*mod_prime)(const struct cczp *zp, cc_unit *r, const cc_unit *s, cc_ws_t ws);
} __attribute__((aligned(CCN_UNIT_SIZE)));

struct cczp_prime {
    struct cczp hdr;
    cc_unit ccn[];
};

typedef union {
    cc_unit *u;
    struct cczp *zp;
    struct cczp_prime *prime;
} cczp_t __attribute__((transparent_union));

typedef union {
    cc_unit *u;
    struct cczp *zp;
    struct cczp_prime *prime;
    struct cczp_short *szp;
    cczp_t _lzp;
} cczp_short_t __attribute__((transparent_union));

typedef union {
    const cc_unit *u;
    const struct cczp *zp;
    const struct cczp_prime *prime;
    cczp_t _nczp;
} cczp_const_t __attribute__((transparent_union));

typedef union {
    const cc_unit *u;
    const struct cczp *zp;
    struct cczp_prime *prime;
    const struct cczp_short *szp;
    cczp_const_t _clzp;
    cczp_short_t _szp;
    cczp_t _lzp;
} cczp_const_short_t __attribute__((transparent_union));

typedef void(ccmod_prime_f)(cczp_const_t, cc_unit *, const cc_unit *, cc_ws_t);

void cczp_init(cczp_t zp);

void cczp_mod(cczp_const_t zp, cc_unit *r, const cc_unit *s2n, cc_ws_t ws);

void cczp_modn(cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s);

void cczp_mul(cczp_const_t zp, cc_unit *t, const cc_unit *x, const cc_unit *y);

void cczp_mul_ws(cczp_const_t zp, cc_unit *t, const cc_unit *x, const cc_unit *y, cc_ws_t ws);

void cczp_sqr(cczp_const_t zp, cc_unit *r, const cc_unit *x);

void cczp_sqr_ws(cczp_const_t zp, cc_unit *r, const cc_unit *x, cc_ws_t ws);

int cczp_sqrt(cczp_const_t zp, cc_unit *r, const cc_unit *x);

void cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *m,
                const cc_unit *e);

void cczp_powern(cczp_const_t zp, cc_unit *r, const cc_unit *s,
                 size_t ebitlen, const cc_unit *e);

void cczp_add(cczp_const_short_t zp, cc_unit *r, const cc_unit *x,
              const cc_unit *y);

void cczp_add_ws(cczp_const_short_t zp, cc_unit *r, const cc_unit *x,
                 const cc_unit *y, cc_ws_t ws);

void cczp_sub(cczp_const_short_t zp, cc_unit *r, const cc_unit *x, const cc_unit *y);

void cczp_sub_ws(cczp_const_short_t zp, cc_unit *r, const cc_unit *x,
                 const cc_unit *y, cc_ws_t ws);

void cczp_div2(cczp_const_short_t zp, cc_unit *r, const cc_unit *x);

void cczp_div(cczp_const_t zd, cc_unit *q, cc_unit *r, const cc_unit *a_2n);

int cczp_mod_inv(cczp_const_short_t zp, cc_unit *r, const cc_unit *x);

int cczp_mod_inv_field(cczp_const_t zp, cc_unit *r, const cc_unit *x);

void cczp_mod_inv_slow(cczp_const_t zp, cc_unit *r, const cc_unit *x);

void cczp_mod_inv_slown(cczp_const_t zp, cc_unit *r, const cc_size nx, const cc_unit *x);

int cczp_rabin_miller(cczp_t zp, unsigned long mr_depth);

int cczp_random_prime(cc_size nbits, cczp_t zp, const cc_unit *e,
                       struct ccrng_state *rng);
#endif
