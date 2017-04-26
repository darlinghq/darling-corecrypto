#ifndef _CORECRYPTO_CCEC_H_
#define _CORECRYPTO_CCEC_H_
#include <corecrypto/ccasn1.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <stdbool.h>
#include <stdarg.h>

cc_aligned_struct(8) ccec_projective_point;

// Structs/unions

typedef union {
    struct ccec_point_hdr *hdr;
    ccec_projective_point *_p;
} __attribute__((transparent_union)) ccec_projective_point_t;

typedef union {
    const struct cczp   *zp;
    const struct cczp_prime *prime;
} __attribute__((transparent_union)) ccec_const_cp_t;

struct ccec_ctx_header {
    ccec_const_cp_t      cp;
    uint8_t              pad[16 - sizeof(ccec_const_cp_t *)];
} __attribute__((aligned(16)));

struct ccec_ctx_public {
    struct ccec_ctx_header  hdr;
    ccec_projective_point point[];
} __attribute__((aligned(16)));

typedef struct ccec_full_ctx {
    struct ccec_ctx_header  hdr;
} __attribute__((aligned(16))) ccec_full_ctx;

typedef union {
    ccec_full_ctx *_full;
    struct ccec_ctx_header *hdr;
    struct ccec_ctx_body *body;
    struct ccec_ctx_public *pub;
} __attribute__((transparent_union)) ccec_full_ctx_t;

typedef struct ccec_pub_ctx {
    struct ccec_ctx_header  hdr;
} __attribute__((aligned(16))) ccec_pub_ctx;

typedef union {
    ccec_pub_ctx *_pub;
    ccec_full_ctx *_full;
    struct ccec_ctx_header *hdr;
    struct ccec_ctx_body *body;
    struct ccec_ctx_public *pub;
    ccec_full_ctx_t fullt;
} __attribute__((transparent_union)) ccec_pub_ctx_t;

struct ccec_ctx_body {
    struct ccec_ctx_header  hdr;
    cc_unit              ccn[];
} __attribute__((aligned(16)));

// Functions needed by the following macros
CC_CONST CC_INLINE
cc_size ccec_cp_n(ccec_const_cp_t cp) {
    return cp.zp->n;
}

CC_CONST CC_INLINE
size_t ccec_ccn_size(ccec_const_cp_t cp) {
    return ccn_sizeof_n(ccec_cp_n(cp));
}

size_t ccec_compact_import_pub_size(size_t in_len);

// Macros
#define ccec_pub_ctx_size(_size_)   (sizeof(struct ccec_ctx_header) + 3 * (_size_))
#define ccec_ctx_cp(KEY)     (((ccec_pub_ctx_t)(KEY)).hdr->cp)
#define ccec_cp_prime_bitlen(CP) (ccn_bitlen((CP).zp->n, (CP).prime->ccn))
#define ccec_ctx_bitlen(KEY) (ccec_cp_prime_bitlen(ccec_ctx_cp(KEY)))
#define ccec_full_ctx_size(_size_)  (sizeof(struct ccec_ctx_header) + 4 * (_size_))
#define ccec_full_ctx_decl(_size_, _name_)  cc_ctx_decl(ccec_full_ctx, ccec_full_ctx_size(_size_), _name_)
#define ccec_full_ctx_decl_cp(_cp_, _name_) ccec_full_ctx_decl(ccec_ccn_size(_cp_), _name_)
#define ccec_pub_ctx_decl(_size_, _name_)   cc_ctx_decl(ccec_pub_ctx, ccec_pub_ctx_size(_size_), _name_)
#define ccec_pub_ctx_decl_cp(_cp_, _name_)  ccec_pub_ctx_decl(ccec_ccn_size(_cp_), _name_)
#define ccec_full_ctx_clear(_size_, _name_) cc_clear(ccec_full_ctx_size(_size_), _name_)
#define ccec_full_ctx_clear_cp(_cp_, _name_) ccec_full_ctx_clear(ccec_ccn_size(_cp_), _name_)
#define ccec_ctx_n(KEY)      (((ccec_pub_ctx_t)(KEY)).hdr->cp.zp->n)
#define ccec_cp_prime_size(CP) ((ccec_cp_prime_bitlen(CP)+7)/8)
#define ccec_ctx_size(KEY) (ccec_cp_prime_size(ccec_ctx_cp(KEY)))

#define ccec_ctx_x(KEY)  (((ccec_pub_ctx_t)(KEY)).body->ccn)
#define ccec_ctx_y(KEY)  (((ccec_pub_ctx_t)(KEY)).body->ccn + 1 * ccec_ctx_n(KEY))
#define ccec_ctx_z(KEY)  (((ccec_pub_ctx_t)(KEY)).body->ccn + 2 * ccec_ctx_n(KEY))
#define ccec_ctx_k(KEY)      (((ccec_full_ctx_t)(KEY)).body->ccn + 3 * ccec_ctx_n(KEY))

#define ccec_ctx_point(KEY)    ((ccec_projective_point_t)(((ccec_pub_ctx_t)(KEY)).pub->point))

// Functions
CC_INLINE CC_CONST CC_NONNULL_TU((2))
size_t ccec_x963_export_size(const int fullkey, ccec_full_ctx_t key){
    return (((ccec_ctx_bitlen(key)+7)/8) * ((fullkey == 1) + 2)) + 1;
}

ccec_const_cp_t ccec_get_cp(size_t keysize);

CC_NONNULL_TU((3)) CC_NONNULL2
void ccec_x963_export(const int fullkey, void *out, ccec_full_ctx_t key);

CC_NONNULL_TU((1,3)) CC_NONNULL2
int ccec_generate_key_legacy(ccec_const_cp_t cp,  struct ccrng_state *rng,
                             ccec_full_ctx_t key);

CC_NONNULL_TU((1))
size_t ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key,
                                  unsigned long flags,
                                  size_t key_len);

#define CCEC_RFC6637_COMPACT_KEYS   1
#define CCEC_RFC6637_DEBUG_KEYS     2

CC_NONNULL_TU((1)) CC_NONNULL((2, 6, 7, 8, 9, 10))
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

CC_NONNULL_TU((1)) CC_NONNULL((2, 3, 5, 6, 7, 8, 10))
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

CC_CONST ccec_const_cp_t ccec_cp_192();
CC_CONST ccec_const_cp_t ccec_cp_224();
CC_CONST ccec_const_cp_t ccec_cp_256();
CC_CONST ccec_const_cp_t ccec_cp_384();

struct ccec_rfc6637_curve;
struct ccec_rfc6637_wrap;
struct ccec_rfc6637_unwrap;

extern struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha256_kek_aes128;
extern struct ccec_rfc6637_wrap ccec_rfc6637_wrap_sha512_kek_aes256;
extern struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha256_kek_aes128;
extern struct ccec_rfc6637_unwrap ccec_rfc6637_unwrap_sha512_kek_aes256;
extern struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p256;
extern struct ccec_rfc6637_curve ccec_rfc6637_dh_curve_p521;

CC_NONNULL_TU((1,3)) CC_NONNULL2
int ccec_compact_generate_key(ccec_const_cp_t cp,  struct ccrng_state *rng,
                              ccec_full_ctx_t key);
CC_NONNULL_TU((3)) CC_NONNULL2
void ccec_compact_export(const int fullkey, void *out, ccec_full_ctx_t key);

CC_INLINE CC_CONST CC_NONNULL_TU((2))
size_t ccec_compact_export_size(const int fullkey, ccec_full_ctx_t key){
    return (((ccec_ctx_bitlen(key)+7)/8) * ((fullkey == 1) + 1));
}

size_t ccec_x963_import_pub_size(size_t in_len);
int ccec_keysize_is_supported(size_t keysize);
size_t ccec_x963_import_priv_size(size_t in_len);

CC_CONST ccec_const_cp_t ccec_cp_192(void);
CC_CONST ccec_const_cp_t ccec_cp_224(void);
CC_CONST ccec_const_cp_t ccec_cp_256(void);
CC_CONST ccec_const_cp_t ccec_cp_384(void);
CC_CONST ccec_const_cp_t ccec_cp_521(void);

CC_NONNULL_TU((1,4)) CC_NONNULL((3))
int ccec_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in,
                    ccec_pub_ctx_t key);

CC_NONNULL_TU((1))
size_t
ccec_signature_r_s_size(ccec_full_ctx_t key);

CC_NONNULL_TU((1)) CC_NONNULL((3, 4, 5, 6))
int ccec_verify_composite(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                          uint8_t *sig_r, uint8_t *sig_s, bool *valid);

CC_NONNULL_TU((1)) CC_NONNULL((3, 5, 6))
int ccec_verify(ccec_pub_ctx_t key, size_t digest_len, const uint8_t *digest,
                size_t sig_len, const uint8_t *sig,  bool *valid);

CC_NONNULL_TU((1)) CC_NONNULL2
void ccec_export_pub(ccec_pub_ctx_t key, void *out);

CC_INLINE CC_CONST CC_NONNULL_TU((1))
size_t ccec_export_pub_size(ccec_pub_ctx_t key) {
    return 1 + 2 * ccec_cp_prime_size(ccec_ctx_cp(key));
}

CC_NONNULL_TU((1,4)) CC_NONNULL((3))
int ccec_der_import_priv(ccec_const_cp_t cp, size_t length, const uint8_t *data, ccec_full_ctx_t full_key);

CC_NONNULL_TU((1,3)) CC_NONNULL2
int ccec_generate_key_fips(ccec_const_cp_t cp,  struct ccrng_state *rng,
                           ccec_full_ctx_t key);

CC_NONNULL_TU((1)) CC_NONNULL((3, 4, 5, 6))
int ccec_sign_composite(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
                        uint8_t *sig_r, uint8_t *sig_s, struct ccrng_state *rng);

CC_NONNULL_TU((1)) CC_NONNULL((3, 4, 5, 6))
int ccec_sign(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
              size_t *sig_len, uint8_t *sig, struct ccrng_state *rng);

CC_NONNULL_TU((3)) CC_NONNULL((2,4))
int ccec_der_import_priv_keytype(size_t len, const uint8_t * data, ccoid_t *oid, size_t *n);

const ccec_const_cp_t ccec_curve_for_length_lookup(size_t keylen, ...);

CC_INLINE
void ccec_ctx_init(ccec_const_cp_t cp, ccec_pub_ctx_t key) {
    key.hdr->cp = cp;
}

size_t ccec_compact_import_pub_size(size_t in_len);

CC_NONNULL_TU((1,4)) CC_NONNULL3
int ccec_compact_import_pub(ccec_const_cp_t cp, size_t in_len, const uint8_t *in, ccec_pub_ctx_t key);

CC_NONNULL_TU((1,2)) CC_NONNULL((3, 4))
int ccec_compute_key(ccec_full_ctx_t private_key, ccec_pub_ctx_t public_key,
                     size_t *computed_key_len, uint8_t *computed_key);

#endif
