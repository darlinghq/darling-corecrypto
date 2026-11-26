/*
 *  ccmldsa.h
 *  corecrypto
 *
 *  Public API declarations, compatible with the corecrypto ML-DSA interface.
 */

#ifndef _CORECRYPTO_CCMLDSA_H_
#define _CORECRYPTO_CCMLDSA_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_fault_canary.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

struct ccmldsa_params;

const struct ccmldsa_params *ccmldsa65(void);
const struct ccmldsa_params *ccmldsa87(void);

#define CCMLDSA65_PUBKEY_NBYTES    1952
#define CCMLDSA65_PRIVKEY_NBYTES   4032
#define CCMLDSA65_SIGNATURE_NBYTES 3309
#define CCMLDSA65_SEED_NBYTES        32

#define CCMLDSA65_PUBKEY_CTX_NBYTES (sizeof(struct ccmldsa_pub_ctx) + CCMLDSA65_PUBKEY_NBYTES)
#define CCMLDSA65_FULLKEY_CTX_NBYTES (sizeof(struct ccmldsa_full_ctx) + CCMLDSA65_PRIVKEY_NBYTES + CCMLDSA65_PUBKEY_NBYTES)

#define ccmldsa65_full_ctx_decl(_name_) cc_ctx_decl(struct ccmldsa_full_ctx, CCMLDSA65_FULLKEY_CTX_NBYTES, _name_)
#define ccmldsa65_full_ctx_clear(_name_) cc_clear(CCMLDSA65_FULLKEY_CTX_NBYTES, _name_)
#define ccmldsa65_pub_ctx_decl(_name_) cc_ctx_decl(struct ccmldsa_pub_ctx, CCMLDSA65_PUBKEY_CTX_NBYTES, _name_)
#define ccmldsa65_pub_ctx_clear(_name_) cc_clear(CCMLDSA65_PUBKEY_CTX_NBYTES, _name_)

#define CCMLDSA87_PUBKEY_NBYTES    2592
#define CCMLDSA87_PRIVKEY_NBYTES   4896
#define CCMLDSA87_SIGNATURE_NBYTES 4627
#define CCMLDSA87_SEED_NBYTES        32

#define CCMLDSA87_PUBKEY_CTX_NBYTES (sizeof(struct ccmldsa_pub_ctx) + CCMLDSA87_PUBKEY_NBYTES)
#define CCMLDSA87_FULLKEY_CTX_NBYTES (sizeof(struct ccmldsa_full_ctx) + CCMLDSA87_PRIVKEY_NBYTES + CCMLDSA87_PUBKEY_NBYTES)

#define ccmldsa87_full_ctx_decl(_name_) cc_ctx_decl(struct ccmldsa_full_ctx, CCMLDSA87_FULLKEY_CTX_NBYTES, _name_)
#define ccmldsa87_full_ctx_clear(_name_) cc_clear(CCMLDSA87_FULLKEY_CTX_NBYTES, _name_)
#define ccmldsa87_pub_ctx_decl(_name_) cc_ctx_decl(struct ccmldsa_pub_ctx, CCMLDSA87_PUBKEY_CTX_NBYTES, _name_)
#define ccmldsa87_pub_ctx_clear(_name_) cc_clear(CCMLDSA87_PUBKEY_CTX_NBYTES, _name_)

typedef struct ccmldsa_full_ctx {
    const struct ccmldsa_params *params;
    uint8_t key[];
} *ccmldsa_full_ctx_t;

CC_NONNULL_ALL
size_t ccmldsa_sizeof_full_ctx(const struct ccmldsa_params *params);

CC_NONNULL_ALL
void ccmldsa_full_ctx_init(ccmldsa_full_ctx_t ctx, const struct ccmldsa_params *params);

#define ccmldsa_full_ctx_decl(_params_, _name_) cc_ctx_decl(struct ccmldsa_full_ctx, ccmldsa_sizeof_full_ctx(_params_), _name_)
#define ccmldsa_full_ctx_clear(_params_, _name_) cc_clear(ccmldsa_sizeof_full_ctx(_params_), _name_)

typedef struct ccmldsa_pub_ctx {
    const struct ccmldsa_params *params;
    uint8_t key[];
} *ccmldsa_pub_ctx_t;

#define ccmldsa_pub_ctx_decl(_params_, _name_) cc_ctx_decl(struct ccmldsa_pub_ctx, ccmldsa_sizeof_pub_ctx(_params_), _name_)
#define ccmldsa_pub_ctx_clear(_params_, _name_) cc_clear(ccmldsa_sizeof_pub_ctx(_params_), _name_)

ccmldsa_pub_ctx_t ccmldsa_public_ctx(ccmldsa_full_ctx_t ctx);

CC_NONNULL_ALL
size_t ccmldsa_sizeof_pub_ctx(const struct ccmldsa_params *params);

CC_NONNULL_ALL
void ccmldsa_pub_ctx_init(ccmldsa_pub_ctx_t ctx, const struct ccmldsa_params *params);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_generate_key(ccmldsa_full_ctx_t key, struct ccrng_state *rng);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_generate_key_with_seed(ccmldsa_full_ctx_t key,
                                   size_t seed_nbytes,
                                   uint8_t *cc_sized_by(seed_nbytes) seed,
                                   struct ccrng_state *rng);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_derive_key_from_seed(ccmldsa_full_ctx_t ctx,
                                 size_t seed_nbytes,
                                 const uint8_t *cc_sized_by(seed_nbytes) seed,
                                 struct ccrng_state *masking_rng);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_sign(ccmldsa_full_ctx_t key,
                 size_t sig_nbytes, uint8_t *cc_sized_by(sig_nbytes) sig,
                 size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg,
                 struct ccrng_state *rng);

CC_NONNULL((1, 3, 5, 8)) CC_WARN_RESULT
int ccmldsa_sign_with_context(ccmldsa_full_ctx_t key,
                              size_t sig_nbytes, uint8_t *cc_sized_by(sig_nbytes) sig,
                              size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg,
                              size_t ctx_nbytes, const uint8_t *cc_sized_by(ctx_nbytes) ctx,
                              struct ccrng_state *rng);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_prehash(ccmldsa_pub_ctx_t pub,
                    size_t hash_nbytes, uint8_t *cc_sized_by(hash_nbytes) hash,
                    size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg);

CC_NONNULL((1, 3, 5)) CC_WARN_RESULT
int ccmldsa_prehash_with_context(ccmldsa_pub_ctx_t pub,
                                 size_t hash_nbytes, uint8_t *cc_sized_by(hash_nbytes) hash,
                                 size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg,
                                 size_t ctx_nbytes, const uint8_t *cc_sized_by(ctx_nbytes) ctx);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_sign_prehashed(ccmldsa_full_ctx_t key,
                           size_t sig_nbytes, uint8_t *cc_sized_by(sig_nbytes) sig,
                           size_t hash_nbytes, const uint8_t *cc_sized_by(hash_nbytes) hash,
                           struct ccrng_state *rng);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_verify(ccmldsa_pub_ctx_t pub,
                   size_t sig_nbytes, const uint8_t *cc_sized_by(sig_nbytes) sig,
                   size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_verify_with_canary(ccmldsa_pub_ctx_t pub,
                               size_t sig_nbytes, const uint8_t *cc_sized_by(sig_nbytes) sig,
                               size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg,
                               cc_fault_canary_t fault_canary);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_verify_prehashed(ccmldsa_pub_ctx_t pub,
                             size_t sig_nbytes, const uint8_t *cc_sized_by(sig_nbytes) sig,
                             size_t hash_nbytes, const uint8_t *cc_sized_by(hash_nbytes) hash);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_verify_prehashed_with_canary(ccmldsa_pub_ctx_t pub,
                                         size_t sig_nbytes,
                                         const uint8_t *cc_sized_by(sig_nbytes) sig,
                                         size_t hash_nbytes,
                                         const uint8_t *cc_sized_by(hash_nbytes) hash,
                                         cc_fault_canary_t fault_canary);

CC_NONNULL((1, 3, 5)) CC_WARN_RESULT
int ccmldsa_verify_with_context(ccmldsa_pub_ctx_t pub,
                                size_t sig_nbytes, const uint8_t *cc_sized_by(sig_nbytes) sig,
                                size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg,
                                size_t ctx_nbytes, const uint8_t *cc_sized_by(ctx_nbytes) ctx);

CC_NONNULL((1, 3, 5, 8)) CC_WARN_RESULT
int ccmldsa_verify_with_context_and_canary(ccmldsa_pub_ctx_t pub,
                                           size_t sig_nbytes, const uint8_t *cc_sized_by(sig_nbytes) sig,
                                           size_t msg_nbytes, const uint8_t *cc_sized_by(msg_nbytes) msg,
                                           size_t ctx_nbytes, const uint8_t *cc_sized_by(ctx_nbytes) ctx,
                                           cc_fault_canary_t fault_canary);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_export_pubkey(const ccmldsa_pub_ctx_t ctx,
                          size_t pubkey_nbytes,
                          uint8_t *cc_sized_by(pubkey_nbytes) pubkey);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_import_pubkey(const struct ccmldsa_params *params,
                          size_t pubkey_nbytes,
                          const uint8_t *cc_sized_by(pubkey_nbytes) pubkey,
                          ccmldsa_pub_ctx_t ctx);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_export_privkey(const ccmldsa_full_ctx_t ctx,
                           size_t privkey_nbytes,
                           uint8_t *cc_sized_by(privkey_nbytes) privkey);

CC_NONNULL_ALL CC_WARN_RESULT
int ccmldsa_import_privkey(const struct ccmldsa_params *params,
                           size_t privkey_nbytes,
                           const uint8_t *cc_sized_by(privkey_nbytes) privkey,
                           ccmldsa_full_ctx_t ctx);

CC_NONNULL_ALL
size_t ccmldsa_pubkey_nbytes_params(const struct ccmldsa_params *params);

CC_NONNULL_ALL
size_t ccmldsa_pubkey_nbytes_ctx(const ccmldsa_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t ccmldsa_privkey_nbytes_params(const struct ccmldsa_params *params);

CC_NONNULL_ALL
size_t ccmldsa_privkey_nbytes_ctx(const ccmldsa_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t ccmldsa_signature_nbytes_params(const struct ccmldsa_params *params);

CC_NONNULL_ALL
size_t ccmldsa_signature_nbytes_ctx(const ccmldsa_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t ccmldsa_seed_nbytes_params(const struct ccmldsa_params *params);

CC_NONNULL_ALL
size_t ccmldsa_seed_nbytes_ctx(const ccmldsa_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t ccmldsa_hash_nbytes_params(const struct ccmldsa_params *params);

CC_NONNULL_ALL
size_t ccmldsa_hash_nbytes_ctx(const ccmldsa_pub_ctx_t ctx);

CC_END_DECLS

#endif /* _CORECRYPTO_CCMLDSA_H_ */
