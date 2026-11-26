/*
 * ML-DSA (FIPS 204) support through the corecrypto signature interface.
 *
 * The polynomial/ring arithmetic comes from the CC0 PQClean clean
 * implementations of ML-DSA-65 and ML-DSA-87 (src/pqc).
 */

#include "pqc/pqc_internal.h"
#include "fips202.h"
#include <corecrypto/ccmldsa.h>
#include <string.h>

/* The two PQClean backends use unprefixed parameter macros, so only their
 * public entry points are declared here. */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_derand(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *rnd, const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_prehash_derand(uint8_t *sig, size_t *siglen,
        const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *rnd, const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx_prehash(const uint8_t *sig, size_t siglen,
        const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx_derand(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *rnd, const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx_prehash_derand(uint8_t *sig, size_t *siglen,
        const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *rnd, const uint8_t *sk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx_prehash(const uint8_t *sig, size_t siglen,
        const uint8_t *ph, size_t phlen, const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

typedef int (*mldsa_keypair_fn)(uint8_t *, uint8_t *, const uint8_t[32]);
typedef int (*mldsa_sign_fn)(uint8_t *, size_t *, const uint8_t *, size_t,
                             const uint8_t *, size_t, const uint8_t *, const uint8_t *);
typedef int (*mldsa_verify_fn)(const uint8_t *, size_t, const uint8_t *, size_t,
                               const uint8_t *, size_t, const uint8_t *);

struct ccmldsa_params {
    size_t pubkey_nbytes;
    size_t privkey_nbytes;
    size_t sig_nbytes;
    size_t seed_nbytes;
    size_t hash_nbytes;
    mldsa_keypair_fn keypair_derand;
    mldsa_sign_fn sign_ctx_derand;
    mldsa_sign_fn sign_prehash_derand;
    mldsa_verify_fn verify_ctx;
    mldsa_verify_fn verify_prehash;
};

static const struct ccmldsa_params mldsa65_params;
static const struct ccmldsa_params mldsa87_params;

const struct ccmldsa_params *ccmldsa65(void) {
    return &mldsa65_params;
}

const struct ccmldsa_params *ccmldsa87(void) {
    return &mldsa87_params;
}

static const struct ccmldsa_params mldsa65_params = {
    .pubkey_nbytes = CCMLDSA65_PUBKEY_NBYTES,
    .privkey_nbytes = CCMLDSA65_PRIVKEY_NBYTES,
    .sig_nbytes = CCMLDSA65_SIGNATURE_NBYTES,
    .seed_nbytes = CCMLDSA65_SEED_NBYTES,
    .hash_nbytes = 64,
    .keypair_derand = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_derand,
    .sign_ctx_derand = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_derand,
    .sign_prehash_derand = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_prehash_derand,
    .verify_ctx = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx,
    .verify_prehash = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx_prehash,
};

static const struct ccmldsa_params mldsa87_params = {
    .pubkey_nbytes = CCMLDSA87_PUBKEY_NBYTES,
    .privkey_nbytes = CCMLDSA87_PRIVKEY_NBYTES,
    .sig_nbytes = CCMLDSA87_SIGNATURE_NBYTES,
    .seed_nbytes = CCMLDSA87_SEED_NBYTES,
    .hash_nbytes = 64,
    .keypair_derand = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_derand,
    .sign_ctx_derand = PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx_derand,
    .sign_prehash_derand = PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx_prehash_derand,
    .verify_ctx = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx,
    .verify_prehash = PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx_prehash,
};

/* Key material is stored as pubkey || privkey, matching the context sizes. */
CC_INLINE uint8_t *mldsa_pubkey(ccmldsa_pub_ctx_t ctx) {
    return ctx->key;
}
CC_INLINE const uint8_t *mldsa_const_pubkey(const ccmldsa_pub_ctx_t ctx) {
    return ctx->key;
}
CC_INLINE uint8_t *mldsa_privkey(ccmldsa_full_ctx_t ctx) {
    return ctx->key + ctx->params->pubkey_nbytes;
}
CC_INLINE const uint8_t *mldsa_const_privkey(const ccmldsa_full_ctx_t ctx) {
    return ctx->key + ctx->params->pubkey_nbytes;
}

size_t ccmldsa_sizeof_full_ctx(const struct ccmldsa_params *params) {
    return sizeof(struct ccmldsa_full_ctx) + params->pubkey_nbytes + params->privkey_nbytes;
}

void ccmldsa_full_ctx_init(ccmldsa_full_ctx_t ctx, const struct ccmldsa_params *params) {
    ctx->params = params;
}

size_t ccmldsa_sizeof_pub_ctx(const struct ccmldsa_params *params) {
    return sizeof(struct ccmldsa_pub_ctx) + params->pubkey_nbytes;
}

void ccmldsa_pub_ctx_init(ccmldsa_pub_ctx_t ctx, const struct ccmldsa_params *params) {
    ctx->params = params;
}

ccmldsa_pub_ctx_t ccmldsa_public_ctx(ccmldsa_full_ctx_t ctx) {
    return (ccmldsa_pub_ctx_t)ctx;
}

int ccmldsa_generate_key_with_seed(ccmldsa_full_ctx_t key,
                                   size_t seed_nbytes,
                                   uint8_t *seed,
                                   struct ccrng_state *rng) {
    if (seed_nbytes != key->params->seed_nbytes) {
        return CCERR_PARAMETER;
    }
    if (ccrng_generate(rng, seed_nbytes, seed) != 0) {
        return CCERR_INTERNAL;
    }
    return ccmldsa_derive_key_from_seed(key, seed_nbytes, seed, rng);
}

int ccmldsa_generate_key(ccmldsa_full_ctx_t key, struct ccrng_state *rng) {
    uint8_t seed[32];
    if (ccrng_generate(rng, sizeof(seed), seed) != 0) {
        return CCERR_INTERNAL;
    }
    return ccmldsa_derive_key_from_seed(key, sizeof(seed), seed, rng);
}

int ccmldsa_derive_key_from_seed(ccmldsa_full_ctx_t ctx,
                                 size_t seed_nbytes,
                                 const uint8_t *seed,
                                 struct ccrng_state *masking_rng) {
    const struct ccmldsa_params *params = ctx->params;
    (void)masking_rng;
    if (seed_nbytes != params->seed_nbytes) {
        return CCERR_PARAMETER;
    }
    ccmldsa_full_ctx_init(ctx, params);
    return params->keypair_derand(mldsa_pubkey((ccmldsa_pub_ctx_t)ctx),
                                  mldsa_privkey(ctx), seed) == 0 ? CCERR_OK : CCERR_INTERNAL;
}

static int mldsa_sign_internal(ccmldsa_full_ctx_t key,
                               size_t sig_nbytes, uint8_t *sig,
                               const uint8_t *msg, size_t msg_nbytes,
                               const uint8_t *ctx, size_t ctx_nbytes,
                               int prehash, struct ccrng_state *rng) {
    const struct ccmldsa_params *params = key->params;
    uint8_t rnd[32];
    size_t siglen = 0;
    int status;

    if (sig_nbytes < params->sig_nbytes || ctx_nbytes > 255) {
        return CCERR_PARAMETER;
    }
    if (ccrng_generate(rng, sizeof(rnd), rnd) != 0) {
        return CCERR_INTERNAL;
    }
    if (prehash) {
        status = params->sign_prehash_derand(sig, &siglen, msg, msg_nbytes,
                                             ctx, ctx_nbytes, rnd, mldsa_const_privkey(key));
    } else {
        status = params->sign_ctx_derand(sig, &siglen, msg, msg_nbytes,
                                         ctx, ctx_nbytes, rnd, mldsa_const_privkey(key));
    }
    cc_clear(sizeof(rnd), rnd);
    if (status != 0 || siglen != params->sig_nbytes) {
        return CCERR_INTERNAL;
    }
    return CCERR_OK;
}

int ccmldsa_sign(ccmldsa_full_ctx_t key,
                 size_t sig_nbytes, uint8_t *sig,
                 size_t msg_nbytes, const uint8_t *msg,
                 struct ccrng_state *rng) {
    return mldsa_sign_internal(key, sig_nbytes, sig, msg, msg_nbytes, NULL, 0, 0, rng);
}

int ccmldsa_sign_with_context(ccmldsa_full_ctx_t key,
                              size_t sig_nbytes, uint8_t *sig,
                              size_t msg_nbytes, const uint8_t *msg,
                              size_t ctx_nbytes, const uint8_t *ctx,
                              struct ccrng_state *rng) {
    return mldsa_sign_internal(key, sig_nbytes, sig, msg, msg_nbytes, ctx, ctx_nbytes, 0, rng);
}

int ccmldsa_sign_prehashed(ccmldsa_full_ctx_t key,
                           size_t sig_nbytes, uint8_t *sig,
                           size_t hash_nbytes, const uint8_t *hash,
                           struct ccrng_state *rng) {
    if (hash_nbytes != key->params->hash_nbytes) {
        return CCERR_PARAMETER;
    }
    return mldsa_sign_internal(key, sig_nbytes, sig, hash, hash_nbytes, NULL, 0, 1, rng);
}

/* FIPS 204 Hash ML-DSA: PH(M) = CRH(tr || 01 || ctxlen || ctx || M). */
static int mldsa_prehash_internal(ccmldsa_pub_ctx_t pub,
                                  size_t hash_nbytes, uint8_t *hash,
                                  const uint8_t *msg, size_t msg_nbytes,
                                  const uint8_t *ctx, size_t ctx_nbytes) {
    const struct ccmldsa_params *params = pub->params;
    uint8_t tr[64];
    uint8_t domain[2] = {1, (uint8_t)ctx_nbytes};
    shake256incctx state;

    if (hash_nbytes < params->hash_nbytes || ctx_nbytes > 255) {
        return CCERR_PARAMETER;
    }
    shake256(tr, sizeof(tr), mldsa_const_pubkey(pub), params->pubkey_nbytes);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, sizeof(tr));
    shake256_inc_absorb(&state, domain, sizeof(domain));
    if (ctx_nbytes != 0) {
        shake256_inc_absorb(&state, ctx, ctx_nbytes);
    }
    shake256_inc_absorb(&state, msg, msg_nbytes);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(hash, hash_nbytes, &state);
    shake256_inc_ctx_release(&state);
    cc_clear(sizeof(tr), tr);
    return CCERR_OK;
}

int ccmldsa_prehash(ccmldsa_pub_ctx_t pub,
                    size_t hash_nbytes, uint8_t *hash,
                    size_t msg_nbytes, const uint8_t *msg) {
    return mldsa_prehash_internal(pub, hash_nbytes, hash, msg, msg_nbytes, NULL, 0);
}

int ccmldsa_prehash_with_context(ccmldsa_pub_ctx_t pub,
                                 size_t hash_nbytes, uint8_t *hash,
                                 size_t msg_nbytes, const uint8_t *msg,
                                 size_t ctx_nbytes, const uint8_t *ctx) {
    return mldsa_prehash_internal(pub, hash_nbytes, hash, msg, msg_nbytes, ctx, ctx_nbytes);
}

static int mldsa_verify_internal(ccmldsa_pub_ctx_t pub,
                                 size_t sig_nbytes, const uint8_t *sig,
                                 const uint8_t *data, size_t data_nbytes,
                                 const uint8_t *ctx, size_t ctx_nbytes,
                                 int prehash) {
    const struct ccmldsa_params *params = pub->params;
    if (sig_nbytes != params->sig_nbytes || ctx_nbytes > 255) {
        return CCERR_INVALID_SIGNATURE;
    }
    if (prehash && data_nbytes != params->hash_nbytes) {
        return CCERR_INVALID_SIGNATURE;
    }
    int status = prehash
        ? params->verify_prehash(sig, sig_nbytes, data, data_nbytes, ctx, ctx_nbytes,
                                 mldsa_const_pubkey(pub))
        : params->verify_ctx(sig, sig_nbytes, data, data_nbytes, ctx, ctx_nbytes,
                             mldsa_const_pubkey(pub));
    return status == 0 ? CCERR_VALID_SIGNATURE : CCERR_INVALID_SIGNATURE;
}

static int mldsa_verify_canary(int status, cc_fault_canary_t fault_canary) {
    if (status == CCERR_VALID_SIGNATURE) {
        CC_FAULT_CANARY_MEMCPY(fault_canary, CCMLDSA_FAULT_CANARY);
    } else {
        CC_FAULT_CANARY_CLEAR(fault_canary);
    }
    return status;
}

int ccmldsa_verify(ccmldsa_pub_ctx_t pub,
                   size_t sig_nbytes, const uint8_t *sig,
                   size_t msg_nbytes, const uint8_t *msg) {
    return mldsa_verify_internal(pub, sig_nbytes, sig, msg, msg_nbytes, NULL, 0, 0);
}

int ccmldsa_verify_with_canary(ccmldsa_pub_ctx_t pub,
                               size_t sig_nbytes, const uint8_t *sig,
                               size_t msg_nbytes, const uint8_t *msg,
                               cc_fault_canary_t fault_canary) {
    int status = ccmldsa_verify(pub, sig_nbytes, sig, msg_nbytes, msg);
    return mldsa_verify_canary(status, fault_canary);
}

int ccmldsa_verify_prehashed(ccmldsa_pub_ctx_t pub,
                             size_t sig_nbytes, const uint8_t *sig,
                             size_t hash_nbytes, const uint8_t *hash) {
    return mldsa_verify_internal(pub, sig_nbytes, sig, hash, hash_nbytes, NULL, 0, 1);
}

int ccmldsa_verify_prehashed_with_canary(ccmldsa_pub_ctx_t pub,
                                         size_t sig_nbytes, const uint8_t *sig,
                                         size_t hash_nbytes, const uint8_t *hash,
                                         cc_fault_canary_t fault_canary) {
    int status = ccmldsa_verify_prehashed(pub, sig_nbytes, sig, hash_nbytes, hash);
    return mldsa_verify_canary(status, fault_canary);
}

int ccmldsa_verify_with_context(ccmldsa_pub_ctx_t pub,
                                size_t sig_nbytes, const uint8_t *sig,
                                size_t msg_nbytes, const uint8_t *msg,
                                size_t ctx_nbytes, const uint8_t *ctx) {
    return mldsa_verify_internal(pub, sig_nbytes, sig, msg, msg_nbytes, ctx, ctx_nbytes, 0);
}

int ccmldsa_verify_with_context_and_canary(ccmldsa_pub_ctx_t pub,
                                           size_t sig_nbytes, const uint8_t *sig,
                                           size_t msg_nbytes, const uint8_t *msg,
                                           size_t ctx_nbytes, const uint8_t *ctx,
                                           cc_fault_canary_t fault_canary) {
    int status = ccmldsa_verify_with_context(pub, sig_nbytes, sig, msg_nbytes, msg,
                                             ctx_nbytes, ctx);
    return mldsa_verify_canary(status, fault_canary);
}

int ccmldsa_export_pubkey(const ccmldsa_pub_ctx_t ctx,
                          size_t pubkey_nbytes, uint8_t *pubkey) {
    size_t nbytes = ctx->params->pubkey_nbytes;
    if (pubkey_nbytes < nbytes) {
        return CCERR_PARAMETER;
    }
    memcpy(pubkey, mldsa_const_pubkey(ctx), nbytes);
    return CCERR_OK;
}

int ccmldsa_import_pubkey(const struct ccmldsa_params *params,
                          size_t pubkey_nbytes, const uint8_t *pubkey,
                          ccmldsa_pub_ctx_t ctx) {
    if (pubkey_nbytes != params->pubkey_nbytes) {
        return CCERR_PARAMETER;
    }
    ccmldsa_pub_ctx_init(ctx, params);
    memcpy(mldsa_pubkey(ctx), pubkey, pubkey_nbytes);
    return CCERR_OK;
}

int ccmldsa_export_privkey(const ccmldsa_full_ctx_t ctx,
                           size_t privkey_nbytes, uint8_t *privkey) {
    size_t nbytes = ctx->params->privkey_nbytes;
    if (privkey_nbytes < nbytes) {
        return CCERR_PARAMETER;
    }
    memcpy(privkey, mldsa_const_privkey(ctx), nbytes);
    return CCERR_OK;
}

int ccmldsa_import_privkey(const struct ccmldsa_params *params,
                           size_t privkey_nbytes, const uint8_t *privkey,
                           ccmldsa_full_ctx_t ctx) {
    if (privkey_nbytes != params->privkey_nbytes) {
        return CCERR_PARAMETER;
    }
    ccmldsa_full_ctx_init(ctx, params);
    memcpy(mldsa_privkey(ctx), privkey, privkey_nbytes);
    return CCERR_OK;
}

size_t ccmldsa_pubkey_nbytes_params(const struct ccmldsa_params *params) {
    return params->pubkey_nbytes;
}
size_t ccmldsa_pubkey_nbytes_ctx(const ccmldsa_pub_ctx_t ctx) {
    return ccmldsa_pubkey_nbytes_params(ctx->params);
}
size_t ccmldsa_privkey_nbytes_params(const struct ccmldsa_params *params) {
    return params->privkey_nbytes;
}
size_t ccmldsa_privkey_nbytes_ctx(const ccmldsa_pub_ctx_t ctx) {
    return ccmldsa_privkey_nbytes_params(ctx->params);
}
size_t ccmldsa_signature_nbytes_params(const struct ccmldsa_params *params) {
    return params->sig_nbytes;
}
size_t ccmldsa_signature_nbytes_ctx(const ccmldsa_pub_ctx_t ctx) {
    return ccmldsa_signature_nbytes_params(ctx->params);
}
size_t ccmldsa_seed_nbytes_params(const struct ccmldsa_params *params) {
    return params->seed_nbytes;
}
size_t ccmldsa_seed_nbytes_ctx(const ccmldsa_pub_ctx_t ctx) {
    return ccmldsa_seed_nbytes_params(ctx->params);
}
size_t ccmldsa_hash_nbytes_params(const struct ccmldsa_params *params) {
    return params->hash_nbytes;
}
size_t ccmldsa_hash_nbytes_ctx(const ccmldsa_pub_ctx_t ctx) {
    return ccmldsa_hash_nbytes_params(ctx->params);
}
