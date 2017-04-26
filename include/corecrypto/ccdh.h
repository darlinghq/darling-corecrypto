#ifndef _CORECRYPTO_CCDH_H_
#define _CORECRYPTO_CCDH_H_

#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>

#define CCDH_ERROR_DEFAULT                  -1
#define CCDH_GENERATE_KEY_TOO_MANY_TRIES    -2
#define CCDH_NOT_SUPPORTED_CONFIGURATION    -3
#define CCDH_SAFETY_CHECK                   -4
#define CCDH_PUBLIC_KEY_MISSING             -5
#define CCDH_INVALID_DOMAIN_PARAMETER       -6
#define CCDH_INVALID_INPUT                  -7
#define CCDH_DOMAIN_PARAMETER_MISMATCH      -8

cc_aligned_struct(16) ccdh_gp;

// Unions/structs

typedef union {
    cczp_t  zp;
    ccdh_gp *gp;   
} __attribute__((transparent_union)) ccdh_gp_t;

typedef union {
    cczp_const_t   zp;          
    const ccdh_gp  *gp;       
    ccdh_gp_t      _ncgp;
} __attribute__((transparent_union)) ccdh_const_gp_t;

struct ccdh_ctx_header {
    ccdh_const_gp_t     gp;
    uint8_t             pad[16 - sizeof(ccdh_const_gp_t *)];
} __attribute__((aligned(16)));

struct ccdh_ctx_body {
    struct ccdh_ctx_header  hdr;
    cc_unit              ccn[];
} __attribute__((aligned(16)));

struct ccdh_ctx_public {
    struct ccdh_ctx_header  hdr;
    cc_unit pub[];
} __attribute__((aligned(16)));

typedef struct ccdh_full_ctx {
    struct ccdh_ctx_header  hdr;
} __attribute__((aligned(16))) ccdh_full_ctx;

typedef union {
    ccdh_full_ctx *_full;
    struct ccdh_ctx_header *hdr;
    struct ccdh_ctx_body *body;
    struct ccdh_ctx_public *pub;
} __attribute__((transparent_union)) ccdh_full_ctx_t;

typedef struct ccdh_pub_ctx {
    struct ccdh_ctx_header  hdr;
} __attribute__((aligned(16))) ccdh_pub_ctx;

typedef union {
    ccdh_pub_ctx *_pub;
    ccdh_full_ctx *_full;
    struct ccdh_ctx_header *hdr;
    struct ccdh_ctx_body *body;
    struct ccdh_ctx_public *pub;
    ccdh_full_ctx_t fullt;
} __attribute__((transparent_union)) ccdh_pub_ctx_t;

// Functions
CC_NONNULL_TU((1,2)) CC_NONNULL3
int ccdh_compute_key(ccdh_full_ctx_t private_key, ccdh_pub_ctx_t public_key,
                     cc_unit *computed_key);

CC_NONNULL_TU((1)) CC_NONNULL3
int ccdh_import_pub(ccdh_const_gp_t gp, size_t in_len, const uint8_t *in,
                    ccdh_pub_ctx_t key);

CC_CONST CC_INLINE CC_NONNULL_TU((1))
cc_size ccdh_gp_n(ccdh_const_gp_t gp) {
    return cczp_n(gp.zp);
}

CC_NONNULL_TU((1)) CC_NONNULL2
int ccdh_generate_key(ccdh_const_gp_t gp, struct ccrng_state *rng,
                      ccdh_full_ctx_t key);

CC_CONST CC_INLINE CC_NONNULL_TU((1))
size_t ccdh_ccn_size(ccdh_const_gp_t gp) {
    return ccn_sizeof_n(cczp_n(gp.zp));
}

// Macros
#define ccdh_pub_ctx_decl(_size_, _name_)   cc_ctx_decl(ccdh_pub_ctx, ccdh_pub_ctx_size(_size_), _name_)

#define ccdh_pub_ctx_decl_gp(_gp_, _name_)  ccdh_pub_ctx_decl(ccdh_ccn_size(_gp_), _name_)

#define ccdh_ctx_y(KEY)  (((ccdh_pub_ctx_t)(KEY)).body->ccn)

#define ccdh_full_ctx_size(_size_)  (sizeof(struct ccdh_ctx_header) + 2 * (_size_))

#define ccdh_gp_size(_size_) (cczp_size(_size_) + 2 * (_size_) + ccn_sizeof_n(1))

#define CCDH_GP_PRIME(_gp_)     (CCZP_PRIME((_gp_).zp))

#define CCDH_GP_N(_gp_)         (CCZP_N((_gp_).zp))

#define CCDH_GP_RECIP(_gp_)     (CCZP_RECIP((_gp_).zp))
#define CCDH_GP_G(_gp_)         (CCDH_GP_RECIP(_gp_) + 1 + ccdh_gp_n(_gp_))
#define CCDH_GP_N(_gp_)         (CCZP_N((_gp_).zp))
#define CCDH_GP_Q(_gp_)         (CCDH_GP_G(_gp_) + ccdh_gp_n(_gp_))
#define CCDH_GP_L(_gp_)         (*(cc_size *)((cc_unit *)(CCDH_GP_Q(_gp_) + ccdh_gp_n(_gp_))))

#define ccdh_pub_ctx_size(_size_)   (sizeof(struct ccdh_ctx_header) + 1 * (_size_))

#endif
