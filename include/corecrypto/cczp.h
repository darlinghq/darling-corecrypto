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

#define CCZP_PRIME(ZP) (((cczp_short_t)(ZP)).prime->ccn)

// Macros

#define CCZP_RECIP(ZP) (((cczp_t)(ZP)).prime->ccn + cczp_n(ZP))
#define cczp_size(_size_) (sizeof(struct cczp) + ccn_sizeof_n(1) + 2 * (_size_))
#define CCZP_N(ZP) (((cczp_short_t)(ZP)).zp->n)
#define CCZP_MOD_PRIME(ZP) (((cczp_short_t)(ZP)).zp->mod_prime)

// Functions

CC_CONST CC_INLINE cc_size cczp_n(cczp_const_short_t zp)
{
	return zp.zp->n;
}

CC_CONST CC_INLINE const cc_unit *cczp_recip(cczp_const_t zp)
{
	return zp.u + cczp_n(zp) + ccn_nof_size(sizeof(struct cczp));
}

CC_CONST CC_INLINE const cc_unit *cczp_prime(cczp_const_short_t zp)
{
	return zp.u + ccn_nof_size(sizeof(struct cczp));
}

CC_CONST CC_INLINE ccmod_prime_f *cczp_mod_prime(cczp_const_t zp)
{
	return zp.zp->mod_prime;
}

void cczp_init(cczp_t zp);

void cczp_mod(cczp_const_t zp, cc_unit *r, const cc_unit *s2n, cc_ws_t ws);

void cczp_power(cczp_const_t zp, cc_unit *r, const cc_unit *m,
                const cc_unit *e);

#endif
