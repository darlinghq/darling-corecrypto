#ifndef _CORECRYPTO_CCEC_H_
#define _CORECRYPTO_CCEC_H_
#include <corecrypto/ccasn1.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <stdbool.h>
#include <stdarg.h>

cc_aligned_struct(8) ccec_projective_point;

struct ccec_point_hdr {
    cc_unit x;
};

typedef union {
    struct ccec_point_hdr *hdr;
    ccec_projective_point *_p;
} __attribute__((transparent_union)) ccec_projective_point_t;

typedef union {
    const struct ccec_point_hdr *hdr;
    ccec_projective_point_t point;
    ccec_projective_point *_p;
    const ccec_projective_point *_cp;
} __attribute__((transparent_union)) ccec_const_projective_point_t;

cc_aligned_struct(8) ccec_affine_point;

typedef union {
    struct ccec_point_hdr *hdr;
    ccec_projective_point_t point;
    ccec_affine_point *_a;
    ccec_projective_point *_p;
} __attribute__((transparent_union)) ccec_affine_point_t;

typedef union {
    const struct ccec_point_hdr *hdr;
    const cc_unit *x;
    ccec_affine_point_t ap;
    ccec_projective_point_t p;
    ccec_const_projective_point_t cp;
    ccec_affine_point *_a;
    const ccec_affine_point *_ca;
    ccec_projective_point *_p;
    const ccec_projective_point *_cp;
} __attribute__((transparent_union)) ccec_const_affine_point_t;

typedef union {
    const struct cczp   *zp;
    const struct cczp_prime *prime;
} __attribute__((transparent_union)) ccec_const_cp_t;


struct ccec_ctx_header {
    ccec_const_cp_t      cp;
    uint8_t              pad[16 - sizeof(ccec_const_cp_t *)];
} __attribute__((aligned(16)));

struct ccec_ctx_body {
    struct ccec_ctx_header  hdr;
    cc_unit              ccn[];
} __attribute__((aligned(16)));

struct ccec_ctx_public {
    struct ccec_ctx_header  hdr;
    ccec_projective_point point[];
} __attribute__((aligned(16)));

typedef struct ccec_full_ctx {
    struct ccec_ctx_header  hdr;
} __attribute__((aligned(16))) ccec_full_ctx;

typedef struct ccec_pub_ctx {
    struct ccec_ctx_header  hdr;
} __attribute__((aligned(16))) ccec_pub_ctx;

typedef union {
    ccec_full_ctx *_full;
    struct ccec_ctx_header *hdr;
    struct ccec_ctx_body *body;
    struct ccec_ctx_public *pub;
} __attribute__((transparent_union)) ccec_full_ctx_t;

typedef union {
    ccec_pub_ctx *_pub;
    ccec_full_ctx *_full;
    struct ccec_ctx_header *hdr;
    struct ccec_ctx_body *body;
    struct ccec_ctx_public *pub;
    ccec_full_ctx_t fullt;
} __attribute__((transparent_union)) ccec_pub_ctx_t;

typedef union {
    const ccec_full_ctx *_cfull;
    ccec_full_ctx *_full;
    const struct ccec_ctx_header *hdr;
    const struct ccec_ctx_body *body;
    const struct ccec_ctx_public *pub;
    ccec_full_ctx_t _fullt;
} __attribute__((transparent_union)) ccec_full_ctx_in_t;

typedef union {
    const ccec_pub_ctx *_cpub; 
    const ccec_full_ctx *_cfull;   
    ccec_pub_ctx *_pub;    
    ccec_full_ctx *_full; 
    const struct ccec_ctx_header *hdr;
    const struct ccec_ctx_body *body;
    const struct ccec_ctx_pub *pub;
    ccec_full_ctx_t _fullt;       
    ccec_full_ctx_in_t _cfullt;    
} __attribute__((transparent_union)) ccec_pub_ctx_in_t;

CC_CONST ccec_const_cp_t ccec_cp_192(void);
CC_CONST ccec_const_cp_t ccec_cp_224(void);
CC_CONST ccec_const_cp_t ccec_cp_256(void);
CC_CONST ccec_const_cp_t ccec_cp_384(void);
CC_CONST ccec_const_cp_t ccec_cp_521(void);

struct ccec_rfc6637_curve;
struct ccec_rfc6637_wrap;
struct ccec_rfc6637_unwrap;

extern struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha256_kek_aes128;
extern struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha512_kek_aes256;
extern struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128;
extern struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256;
extern struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p256;
extern struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p521;

int ccec_generate_key(ccec_const_cp_t cp, struct ccrng_state *rng,
                      ccec_full_ctx_t key);

int ccec_generate_key_legacy(ccec_const_cp_t cp,  struct ccrng_state *rng,
                             ccec_full_ctx_t key);

int ccec_generate_key_fips(ccec_const_cp_t cp,  struct ccrng_state *rng,
                           ccec_full_ctx_t key);

int ccec_compact_generate_key(ccec_const_cp_t cp,  struct ccrng_state *rng,
                              ccec_full_ctx_t key);

int ccec_sign(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
              size_t *sig_len, uint8_t *sig, struct ccrng_state *rng);

int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                size_t sig_len, const uint8_t *sig,  bool *valid);

size_t
ccec_signature_r_s_size(ccec_full_ctx_t key);

int ccec_sign_composite(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
                        uint8_t *sig_r, uint8_t *sig_s, struct ccrng_state *rng);

int ccec_verify_composite(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                          uint8_t *sig_r, uint8_t *sig_s, bool *valid);

int ccec_compute_key(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
                     size_t *computed_key_len, uint8_t *computed_key);

int ccecdh_compute_shared_secret(ccec_full_ctx_t private_key,
                                 ccec_pub_ctx_t public_key,
                                 size_t *computed_shared_secret_len, uint8_t *computed_shared_secret,
                                 struct ccrng_state *masking_rng);



size_t ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key,
                                  unsigned long flags,
                                  size_t key_len);



int ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key,
                          void  *wrapped_key,
                          unsigned long flags,
                          uint8_t algid,
                          size_t key_len,
                          const void *key,
                          const struct ccec_rfc6637_curve *curve,
                          const struct ccec_rfc6637_wrap *wrap,
                          const uint8_t *fingerprint,
                          struct ccrng_state *rng);

 
int ccec_rfc6637_unwrap_key(ccec_full_ctx_t private_key,
                            size_t *key_len,
                            void *key,
                            unsigned long flags,
                            uint8_t *symm_key_alg,
                            const struct ccec_rfc6637_curve *curve,
                            const struct ccec_rfc6637_unwrap *wrap,
                            const uint8_t *fingerprint,
                            size_t wrapped_key_len,
                            const void  *wrapped_key);

int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in,
                    ccec_pub_ctx_t key);

void ccec_export_pub(ccec_pub_ctx_t key, void *out);

size_t
ccec_der_export_priv_size(ccec_full_ctx_t key, ccoid_t key_oid, int includePublic);

int
ccec_der_export_priv(ccec_full_ctx_t key, ccoid_t key_oid, int includePublic, size_t out_len, void *out);

int ccec_der_import_priv_keytype(size_t len, const uint8_t * data, ccoid_t *oid, size_t *n);


int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *data, ccec_full_ctx_t full_key);


void ccec_x963_export(const int fullkey, void *out, ccec_full_ctx_t key);

int ccec_x963_import(const int fullkey, size_t in_len, const uint8_t *in, ccec_full_ctx_t key);

size_t ccec_x963_import_pub_size(size_t in_len);


int ccec_x963_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

size_t ccec_x963_import_priv_size(size_t in_len);

int ccec_x963_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key);

void ccec_compact_export(const int fullkey, void *out, ccec_full_ctx_t key);
 
size_t ccec_compact_import_pub_size(size_t in_len);

int ccec_compact_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

size_t ccec_compact_import_priv_size(size_t in_len);

int ccec_compact_import_priv(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_full_ctx_t key);


int ccec_get_pubkey_components(ccec_pub_ctx_t key, size_t *nbits,
                           uint8_t *x, size_t *xsize,
                           uint8_t *y, size_t *ysize);


int ccec_get_fullkey_components(ccec_full_ctx_t key, size_t *nbits,
                            uint8_t *x, size_t *xsize,
                            uint8_t *y, size_t *ysize,
                            uint8_t *d, size_t *dsize);

int ccec_make_pub(size_t nbits,
                  size_t xlength, uint8_t *x,
                  size_t ylength, uint8_t *y,
                  ccec_pub_ctx_t key);

int ccec_make_priv(size_t nbits,
                   size_t xlength, uint8_t *x,
                   size_t ylength, uint8_t *y,
                   size_t klength, uint8_t *k,
                   ccec_full_ctx_t key);

int ccec_keysize_is_supported(size_t keysize);

ccec_const_cp_t ccec_get_cp(size_t keysize);

bool ccec_pairwise_consistency_check(const ccec_full_ctx_t full_key, struct ccrng_state *rng);

const ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...);

#endif
