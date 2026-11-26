/*
 *  cckem.h
 *  corecrypto
 *
 *  Public API declarations, compatible with the corecrypto KEM interface.
 *  Declarations only: this file carries no implementation from corecrypto.
 */

#ifndef _CORECRYPTO_CCKEM_H_
#define _CORECRYPTO_CCKEM_H_

#include <corecrypto/cc.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

struct cckem_info;

struct cckem_full_ctx {
    const struct cckem_info *info;
    /* uint8_t pubkey[n]; uint8_t privkey[n]; */
};
typedef struct cckem_full_ctx *cckem_full_ctx_t;

CC_NONNULL_ALL
size_t cckem_sizeof_full_ctx(const struct cckem_info *info);

CC_NONNULL_ALL
void cckem_full_ctx_init(cckem_full_ctx_t ctx, const struct cckem_info *info);

#define cckem_full_ctx_decl(_info_, _name_) cc_ctx_decl(struct cckem_full_ctx, cckem_sizeof_full_ctx(_info_), _name_)
#define cckem_full_ctx_clear(_info_, _name_) cc_memset(_name_, 0, cckem_sizeof_full_ctx(_info_))

struct cckem_pub_ctx {
    const struct cckem_info *info;
    /* uint8_t pubkey[n]; */
};
typedef struct cckem_pub_ctx *cckem_pub_ctx_t;

cckem_pub_ctx_t cckem_public_ctx(cckem_full_ctx_t ctx);

CC_NONNULL_ALL
size_t cckem_sizeof_pub_ctx(const struct cckem_info *info);

CC_NONNULL_ALL
void cckem_pub_ctx_init(cckem_pub_ctx_t ctx, const struct cckem_info *info);

#define cckem_pub_ctx_decl(_info_, _name_) cc_ctx_decl(struct cckem_pub_ctx, cckem_sizeof_pub_ctx(_info_), _name_)
#define cckem_pub_ctx_clear(_info_, _name_) memset(_name_, 0, cckem_sizeof_pub_ctx(_info_))

CC_NONNULL_ALL
int cckem_generate_key(cckem_full_ctx_t ctx, struct ccrng_state *rng);

CC_NONNULL_ALL CC_WARN_RESULT
int cckem_generate_key_with_seed(cckem_full_ctx_t ctx,
                                 size_t seed_nbytes,
                                 uint8_t *cc_sized_by(seed_nbytes) seed,
                                 struct ccrng_state *rng);

CC_NONNULL_ALL
int cckem_derive_key_from_seed(cckem_full_ctx_t ctx,
                               size_t seed_nbytes,
                               const uint8_t *cc_sized_by(seed_nbytes) seed,
                               struct ccrng_state *masking_rng);

CC_NONNULL_ALL
int cckem_encapsulate(const cckem_pub_ctx_t ctx,
                      size_t ek_nbytes,
                      uint8_t *cc_sized_by(ek_nbytes) ek,
                      size_t sk_nbytes,
                      uint8_t *cc_sized_by(sk_nbytes) sk,
                      struct ccrng_state *rng);

CC_NONNULL_ALL
int cckem_decapsulate(const cckem_full_ctx_t ctx,
                      size_t ek_nbytes,
                      const uint8_t *cc_sized_by(ek_nbytes) ek,
                      size_t sk_nbytes,
                      uint8_t *cc_sized_by(sk_nbytes) sk);

CC_NONNULL_ALL
int cckem_export_pubkey(const cckem_pub_ctx_t ctx,
                        size_t *pubkey_nbytes,
                        uint8_t *cc_sized_by(*pubkey_nbytes) pubkey);

CC_NONNULL_ALL
int cckem_import_pubkey(const struct cckem_info *info,
                        size_t pubkey_nbytes,
                        const uint8_t *cc_sized_by(pubkey_nbytes) pubkey,
                        cckem_pub_ctx_t ctx);

CC_NONNULL_ALL
int cckem_export_privkey(const cckem_full_ctx_t ctx,
                         size_t *privkey_nbytes,
                         uint8_t *cc_sized_by(*privkey_nbytes) privkey);

CC_NONNULL_ALL
int cckem_import_privkey(const struct cckem_info *info,
                         size_t privkey_nbytes,
                         const uint8_t *cc_sized_by(privkey_nbytes) privkey,
                         cckem_full_ctx_t ctx);

CC_NONNULL_ALL
size_t cckem_encapsulated_key_nbytes_info(const struct cckem_info *info);

CC_NONNULL_ALL
size_t cckem_encapsulated_key_nbytes_ctx(const cckem_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t cckem_shared_key_nbytes_info(const struct cckem_info *info);

CC_NONNULL_ALL
size_t cckem_shared_key_nbytes_ctx(const cckem_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t cckem_pubkey_nbytes_info(const struct cckem_info *info);

CC_NONNULL_ALL
size_t cckem_pubkey_nbytes_ctx(const cckem_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t cckem_privkey_nbytes_info(const struct cckem_info *info);

CC_NONNULL_ALL
size_t cckem_privkey_nbytes_ctx(const cckem_pub_ctx_t ctx);

CC_NONNULL_ALL
size_t cckem_seed_nbytes_info(const struct cckem_info *info);

CC_NONNULL_ALL
size_t cckem_seed_nbytes_ctx(const cckem_pub_ctx_t ctx);

CC_END_DECLS

#endif /* _CORECRYPTO_CCKEM_H_ */
