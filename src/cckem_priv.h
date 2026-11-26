/*
 * Private definition of the KEM descriptor shared by the corecrypto KEM
 * dispatcher and the individual algorithm backends.
 */

#ifndef _DARLING_CCKEM_PRIV_H_
#define _DARLING_CCKEM_PRIV_H_

#include <corecrypto/cckem.h>

struct cckem_info {
    size_t pubkey_nbytes;
    size_t privkey_nbytes;
    size_t ek_nbytes;
    size_t sk_nbytes;
    size_t seed_nbytes;
    size_t encaps_random_nbytes;

    int (*keygen_derand)(const struct cckem_info *info,
                         uint8_t *pk, uint8_t *sk, const uint8_t *seed);
    int (*encaps_derand)(const struct cckem_info *info,
                         const uint8_t *pk, uint8_t *ek, uint8_t *ss,
                         const uint8_t *random);
    int (*decaps)(const struct cckem_info *info,
                  const uint8_t *sk, const uint8_t *ek, uint8_t *ss);
};

CC_INLINE uint8_t *cckem_pubkey(cckem_pub_ctx_t ctx) {
    return (uint8_t *)(ctx + 1);
}

CC_INLINE const uint8_t *cckem_const_pubkey(const cckem_pub_ctx_t ctx) {
    return (const uint8_t *)(ctx + 1);
}

CC_INLINE uint8_t *cckem_full_pubkey(cckem_full_ctx_t ctx) {
    return (uint8_t *)(ctx + 1);
}

CC_INLINE const uint8_t *cckem_const_full_pubkey(const cckem_full_ctx_t ctx) {
    return (const uint8_t *)(ctx + 1);
}

CC_INLINE uint8_t *cckem_privkey(cckem_full_ctx_t ctx) {
    return (uint8_t *)(ctx + 1) + ctx->info->pubkey_nbytes;
}

CC_INLINE const uint8_t *cckem_const_privkey(const cckem_full_ctx_t ctx) {
    return (const uint8_t *)(ctx + 1) + ctx->info->pubkey_nbytes;
}

#endif /* _DARLING_CCKEM_PRIV_H_ */
