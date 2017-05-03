#ifndef _CCRSA_H_
#define _CCRSA_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <stdbool.h>

// Structs / unions

cc_aligned_struct(16) ccrsa_full_ctx;
cc_aligned_struct(16) ccrsa_priv_ctx;
cc_aligned_struct(16) ccrsa_pub_ctx;

typedef union {
    cczp_t zp;
    ccrsa_priv_ctx *priv;
} ccrsa_priv_ctx_t __attribute__((transparent_union));

typedef union {
    cczp_t zp;
    ccrsa_full_ctx *full;
} ccrsa_full_ctx_t __attribute__((transparent_union));

typedef union {
    cczp_t zp;
    ccrsa_pub_ctx *pub;
    ccrsa_full_ctx *full;
    ccrsa_full_ctx_t full_t;
} ccrsa_pub_ctx_t __attribute__((transparent_union));

// Macros

#define ccrsa_ctx_zm(_ctx_)        (((ccrsa_pub_ctx_t)(_ctx_)).zp)
#define ccrsa_ctx_n(_ctx_)         (ccrsa_ctx_zm(_ctx_).zp->n)
#define ccrsa_ctx_m(_ctx_)         (ccrsa_ctx_zm(_ctx_).prime->ccn)
#define ccrsa_ctx_e(_ctx_)         (ccrsa_ctx_m(_ctx_) + 2 * ccrsa_ctx_n(_ctx_) + 1)
#define ccrsa_ctx_d(_ctx_)         (ccrsa_ctx_m(((ccrsa_full_ctx_t)_ctx_)) + 3 * ccrsa_ctx_n(_ctx_) + 1)

#define ccrsa_ctx_private_zq(PRIVK)   ((cczp_t)(((ccrsa_priv_ctx_t)(PRIVK)).zp.prime->ccn + 2 * ccrsa_ctx_private_zp(PRIVK).zp->n + 1))
#define ccrsa_pub_ctx_size(_size_)   (sizeof(struct cczp) + CCN_UNIT_SIZE + 3 * (_size_))
#define ccrsa_ctx_private_zp(PRIVK)   (((ccrsa_priv_ctx_t)(PRIVK)).zp)
#define ccrsa_ctx_private_dq(PRIVK)   (((ccrsa_priv_ctx_t)(PRIVK)).zp.prime->ccn + 5 * ccrsa_ctx_private_zp(PRIVK).zp->n + 2 + ccn_nof_size(sizeof(struct cczp)))
#define ccrsa_ctx_private_qinv(PRIVK) (((ccrsa_priv_ctx_t)(PRIVK)).zp.prime->ccn + 6 * ccrsa_ctx_private_zp(PRIVK).zp->n + 2 + ccn_nof_size(sizeof(struct cczp)))

#define ccrsa_ctx_private_dp(PRIVK)   (((ccrsa_priv_ctx_t)(PRIVK)).zp.prime->ccn + 4 * ccrsa_ctx_private_zp(PRIVK).zp->n + 2 + ccn_nof_size(sizeof(struct cczp)))

#define ccrsa_priv_ctx_size(_size_)  ((sizeof(struct cczp) + CCN_UNIT_SIZE) * 2 + 7 * ccn_sizeof((ccn_bitsof_size(_size_) / 2) + 1))


#define ccrsa_ctx_public(FK)          ((ccrsa_pub_ctx_t)(FK))

#define ccrsa_full_ctx_size(_size_)  (ccrsa_pub_ctx_size(_size_) + _size_ + ccrsa_priv_ctx_size(_size_))

// Functions

CC_CONST CC_INLINE
ccrsa_priv_ctx_t ccrsa_ctx_private(ccrsa_full_ctx_t fk) {
    uint8_t *p = (uint8_t *)fk.full;
    size_t p_size = ccn_sizeof_n(ccrsa_ctx_n(fk));
    p += ccrsa_pub_ctx_size(p_size) + p_size;
    ccrsa_priv_ctx *priv = (ccrsa_priv_ctx *)p;
    return (ccrsa_priv_ctx_t)priv;
}

CC_NONNULL_TU((1)) CC_NONNULL((3))
int ccrsa_import_pub(ccrsa_pub_ctx_t key, size_t inlen, const uint8_t *der);

CC_NONNULL((1)) CC_NONNULL((2))
cc_size ccder_decode_rsa_pub_n(const uint8_t *der, const uint8_t *der_end);

CC_NONNULL_TU((1)) CC_NONNULL((2, 3))
int ccrsa_pub_crypt(ccrsa_pub_ctx_t key, cc_unit *out, const cc_unit *in);

CC_NONNULL_TU((2)) CC_NONNULL((4, 5))
int ccrsa_generate_key(unsigned long nbits, ccrsa_full_ctx_t rsa_ctx,
                       size_t e_size, const void *e, struct ccrng_state *rng);

CC_NONNULL_TU((1)) CC_NONNULL((2, 3))
int ccrsa_priv_crypt(ccrsa_priv_ctx_t key, cc_unit *out, const cc_unit *in);

CC_NONNULL((1)) CC_NONNULL((2))
cc_size ccder_decode_rsa_priv_n(const uint8_t *der, const uint8_t *der_end);

CC_NONNULL_TU((1)) CC_NONNULL((2)) CC_NONNULL((3))
const uint8_t *ccder_decode_rsa_priv(const ccrsa_full_ctx_t key, const uint8_t *der, const uint8_t *der_end);

CC_NONNULL_TU((1)) CC_NONNULL((2, 4, 6, 7))
int ccrsa_verify_pkcs1v15(ccrsa_pub_ctx_t key, const uint8_t *oid,
                          size_t digest_len, const uint8_t *digest,
                          size_t sig_len, const uint8_t *sig,
                          bool *valid);

CC_NONNULL_TU((1)) CC_NONNULL((2, 3))
void ccrsa_init_pub(ccrsa_pub_ctx_t key, const cc_unit *modulus,
                    const cc_unit *e);

#endif
