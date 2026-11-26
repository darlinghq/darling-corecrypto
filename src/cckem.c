/*
 * Generic corecrypto KEM interface.  Algorithm-specific behaviour lives in
 * the cckem_info descriptors supplied by ccmlkem, cckyber and ccxwing.
 */

#include "cckem_priv.h"
#include "pqc/pqc_internal.h"
#include <string.h>

size_t cckem_sizeof_full_ctx(const struct cckem_info *info) {
    return sizeof(struct cckem_full_ctx) + info->pubkey_nbytes + info->privkey_nbytes;
}

void cckem_full_ctx_init(cckem_full_ctx_t ctx, const struct cckem_info *info) {
    ctx->info = info;
}

cckem_pub_ctx_t cckem_public_ctx(cckem_full_ctx_t ctx) {
    return (cckem_pub_ctx_t)ctx;
}

size_t cckem_sizeof_pub_ctx(const struct cckem_info *info) {
    return sizeof(struct cckem_pub_ctx) + info->pubkey_nbytes;
}

void cckem_pub_ctx_init(cckem_pub_ctx_t ctx, const struct cckem_info *info) {
    ctx->info = info;
}

int cckem_generate_key_with_seed(cckem_full_ctx_t ctx,
                                 size_t seed_nbytes,
                                 uint8_t *seed,
                                 struct ccrng_state *rng) {
    const struct cckem_info *info = ctx->info;
    if (seed_nbytes != info->seed_nbytes) {
        return CCERR_PARAMETER;
    }
    if (ccrng_generate(rng, seed_nbytes, seed) != 0) {
        return CCERR_INTERNAL;
    }
    return cckem_derive_key_from_seed(ctx, seed_nbytes, seed, rng);
}

int cckem_generate_key(cckem_full_ctx_t ctx, struct ccrng_state *rng) {
    uint8_t seed[64];
    const struct cckem_info *info = ctx->info;
    if (info->seed_nbytes > sizeof(seed)) {
        return CCERR_PARAMETER;
    }
    if (ccrng_generate(rng, info->seed_nbytes, seed) != 0) {
        return CCERR_INTERNAL;
    }
    return cckem_derive_key_from_seed(ctx, info->seed_nbytes, seed, rng);
}

int cckem_derive_key_from_seed(cckem_full_ctx_t ctx,
                               size_t seed_nbytes,
                               const uint8_t *seed,
                               struct ccrng_state *masking_rng) {
    const struct cckem_info *info = ctx->info;
    if (seed_nbytes != info->seed_nbytes) {
        return CCERR_PARAMETER;
    }
    (void)masking_rng;
    cckem_full_ctx_init(ctx, info);
    return info->keygen_derand(info, cckem_full_pubkey(ctx), cckem_privkey(ctx), seed);
}

int cckem_encapsulate(const cckem_pub_ctx_t ctx,
                      size_t ek_nbytes, uint8_t *ek,
                      size_t sk_nbytes, uint8_t *sk,
                      struct ccrng_state *rng) {
    const struct cckem_info *info = ctx->info;
    uint8_t random[64];
    if (ek_nbytes < info->ek_nbytes || sk_nbytes < info->sk_nbytes ||
        info->encaps_random_nbytes > sizeof(random)) {
        return CCERR_PARAMETER;
    }
    if (ccrng_generate(rng, info->encaps_random_nbytes, random) != 0) {
        return CCERR_INTERNAL;
    }
    pqc_rng_set(rng);
    int status = info->encaps_derand(info, cckem_const_pubkey(ctx), ek, sk, random);
    pqc_rng_set(NULL);
    return status;
}

int cckem_decapsulate(const cckem_full_ctx_t ctx,
                      size_t ek_nbytes, const uint8_t *ek,
                      size_t sk_nbytes, uint8_t *sk) {
    const struct cckem_info *info = ctx->info;
    if (ek_nbytes != info->ek_nbytes || sk_nbytes != info->sk_nbytes) {
        return CCERR_PARAMETER;
    }
    return info->decaps(info, cckem_const_privkey(ctx), ek, sk);
}

int cckem_export_pubkey(const cckem_pub_ctx_t ctx,
                        size_t *pubkey_nbytes, uint8_t *pubkey) {
    const struct cckem_info *info = ctx->info;
    if (*pubkey_nbytes < info->pubkey_nbytes) {
        return CCERR_PARAMETER;
    }
    memcpy(pubkey, cckem_const_pubkey(ctx), info->pubkey_nbytes);
    *pubkey_nbytes = info->pubkey_nbytes;
    return CCERR_OK;
}

int cckem_import_pubkey(const struct cckem_info *info,
                        size_t pubkey_nbytes, const uint8_t *pubkey,
                        cckem_pub_ctx_t ctx) {
    if (pubkey_nbytes != info->pubkey_nbytes) {
        return CCERR_PARAMETER;
    }
    cckem_pub_ctx_init(ctx, info);
    memcpy(cckem_pubkey(ctx), pubkey, pubkey_nbytes);
    return CCERR_OK;
}

int cckem_export_privkey(const cckem_full_ctx_t ctx,
                         size_t *privkey_nbytes, uint8_t *privkey) {
    const struct cckem_info *info = ctx->info;
    if (*privkey_nbytes < info->privkey_nbytes) {
        return CCERR_PARAMETER;
    }
    memcpy(privkey, cckem_const_privkey(ctx), info->privkey_nbytes);
    *privkey_nbytes = info->privkey_nbytes;
    return CCERR_OK;
}

int cckem_import_privkey(const struct cckem_info *info,
                         size_t privkey_nbytes, const uint8_t *privkey,
                         cckem_full_ctx_t ctx) {
    if (privkey_nbytes != info->privkey_nbytes) {
        return CCERR_PARAMETER;
    }
    cckem_full_ctx_init(ctx, info);
    memcpy(cckem_privkey(ctx), privkey, privkey_nbytes);
    return CCERR_OK;
}

size_t cckem_encapsulated_key_nbytes_info(const struct cckem_info *info) {
    return info->ek_nbytes;
}

size_t cckem_encapsulated_key_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_encapsulated_key_nbytes_info(ctx->info);
}

size_t cckem_shared_key_nbytes_info(const struct cckem_info *info) {
    return info->sk_nbytes;
}

size_t cckem_shared_key_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_shared_key_nbytes_info(ctx->info);
}

size_t cckem_pubkey_nbytes_info(const struct cckem_info *info) {
    return info->pubkey_nbytes;
}

size_t cckem_pubkey_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_pubkey_nbytes_info(ctx->info);
}

size_t cckem_privkey_nbytes_info(const struct cckem_info *info) {
    return info->privkey_nbytes;
}

size_t cckem_privkey_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_privkey_nbytes_info(ctx->info);
}

size_t cckem_seed_nbytes_info(const struct cckem_info *info) {
    return info->seed_nbytes;
}

size_t cckem_seed_nbytes_ctx(const cckem_pub_ctx_t ctx) {
    return cckem_seed_nbytes_info(ctx->info);
}
