/*
 * Standalone KAT and negative tests for the Apple-compatible post-quantum
 * interfaces: X-Wing, ML-KEM, Kyber and ML-DSA.
 *
 * Build and run from the repository root:
 *   gcc -w -Iinclude \
 *     $(sed -n '/set(corecrypto_sources/,/^)/p' CMakeLists.txt \
 *       | grep 'src/' | tr -d '\t ' | sort -u) \
 *     $(find src/pqc -name '*.c' | sort) \
 *     tests/standalone/pqc_vectors.c -o /tmp/pqc_vectors && /tmp/pqc_vectors
 */
#include <corecrypto/cckem.h>
#include <corecrypto/ccmlkem.h>
#include <corecrypto/cckyber.h>
#include <corecrypto/ccxwing.h>
#include <corecrypto/ccmldsa.h>
#include <corecrypto/cc_fault_canary.h>
#include <corecrypto/cc_error.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "xwing_vectors.h"
#include "mlkem768_vectors.h"
#include "mlkem1024_vectors.h"
#include "kyber768_vectors.h"
#include "kyber1024_vectors.h"
#include "mldsa65_vectors.h"
#include "mldsa87_vectors.h"

static int checks;
static int failures;

static void checkf(bool ok, const char *fmt, ...)
{
    char what[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(what, sizeof(what), fmt, ap);
    va_end(ap);
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    checks++;
    if (!ok) {
        failures++;
    }
}

static void print_bytes(const char *label, const uint8_t *bytes, size_t n)
{
    size_t i;
    printf("  %s (%zu):", label, n);
    for (i = 0; i < n && i < 32; i++) {
        printf(" %02x", bytes[i]);
    }
    if (n > 32) {
        printf(" ...");
    }
    printf("\n");
}

static void check_bytes(const char *what, const uint8_t *got,
                        const uint8_t *expected, size_t n)
{
    bool ok = got != NULL && expected != NULL && memcmp(got, expected, n) == 0;
    checkf(ok, "%s", what);
    if (!ok) {
        if (got != NULL) {
            print_bytes("got", got, n);
        }
        if (expected != NULL) {
            print_bytes("expected", expected, n);
        }
    }
}

/* A tiny ccrng that replays a fixed byte string. */
struct fixed_rng {
    struct ccrng_state base;
    const uint8_t *bytes;
    size_t length;
    size_t offset;
};

static int fixed_generate(struct ccrng_state *rng, size_t length, void *out)
{
    struct fixed_rng *fixed = (struct fixed_rng *)rng;
    if (fixed->offset + length > fixed->length) {
        return -1;
    }
    memcpy(out, fixed->bytes + fixed->offset, length);
    fixed->offset += length;
    return 0;
}

static void fixed_rng_init(struct fixed_rng *rng, const uint8_t *bytes, size_t length)
{
    rng->base.generate = fixed_generate;
    rng->bytes = bytes;
    rng->length = length;
    rng->offset = 0;
}

static const uint8_t zeros[64] = {0};

/* -------------------------------------------------------------------------
 * KEM vectors
 * ------------------------------------------------------------------------- */

struct kem_kat {
    const char *name;
    const struct cckem_info *(*info)(void);
    const uint8_t *seed;
    size_t seed_nbytes;
    const uint8_t *coins;
    size_t coins_nbytes;
    const uint8_t *pk;
    size_t pk_nbytes;
    size_t priv_nbytes;
    const uint8_t *ct;
    size_t ct_nbytes;
    const uint8_t *ss;
};

static void test_kem_kat(const struct kem_kat *t)
{
    uint8_t pk[2048];
    uint8_t pk2[2048];
    uint8_t priv[4096];
    uint8_t priv2[4096];
    uint8_t ek[2048];
    uint8_t ss[64];
    uint8_t ss2[64];
    uint8_t bad_ek[2048];
    uint8_t seed_out[64];
    struct fixed_rng rng;
    const struct cckem_info *info = t->info();
    size_t n;
    int rv;

    cckem_full_ctx_decl(info, full);
    cckem_full_ctx_decl(info, full2);
    cckem_pub_ctx_decl(info, pub);

    checkf(cckem_pubkey_nbytes_info(info) == t->pk_nbytes,
           "%s: public key size", t->name);
    checkf(cckem_privkey_nbytes_info(info) == t->priv_nbytes,
           "%s: private key size", t->name);
    checkf(cckem_encapsulated_key_nbytes_info(info) == t->ct_nbytes,
           "%s: ciphertext size", t->name);
    checkf(cckem_shared_key_nbytes_info(info) == 32,
           "%s: shared secret size", t->name);
    checkf(cckem_seed_nbytes_info(info) == t->seed_nbytes,
           "%s: seed size", t->name);

    cckem_full_ctx_init(full, info);
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = cckem_derive_key_from_seed(full, t->seed_nbytes, t->seed, &rng.base);
    checkf(rv == 0, "%s: derive_key_from_seed -> %d", t->name, rv);

    n = sizeof(pk);
    rv = cckem_export_pubkey(cckem_public_ctx(full), &n, pk);
    checkf(rv == 0 && n == t->pk_nbytes,
           "%s: export_pubkey -> %d, n=%zu", t->name, rv, n);
    check_bytes(t->name, pk, t->pk, t->pk_nbytes);

    n = sizeof(priv);
    rv = cckem_export_privkey(full, &n, priv);
    checkf(rv == 0 && n == t->priv_nbytes,
           "%s: export_privkey -> %d, n=%zu", t->name, rv, n);

    cckem_pub_ctx_init(pub, info);
    rv = cckem_import_pubkey(info, t->pk_nbytes, t->pk, pub);
    checkf(rv == 0, "%s: import_pubkey -> %d", t->name, rv);
    n = sizeof(pk2);
    rv = cckem_export_pubkey(pub, &n, pk2);
    checkf(rv == 0 && n == t->pk_nbytes,
           "%s: imported public key round trip -> %d", t->name, rv);
    check_bytes(t->name, pk2, t->pk, t->pk_nbytes);

    cckem_full_ctx_init(full2, info);
    rv = cckem_import_privkey(info, t->priv_nbytes, priv, full2);
    checkf(rv == 0, "%s: import_privkey -> %d", t->name, rv);
    n = sizeof(priv2);
    rv = cckem_export_privkey(full2, &n, priv2);
    checkf(rv == 0 && n == t->priv_nbytes,
           "%s: imported private key round trip -> %d", t->name, rv);
    check_bytes(t->name, priv2, priv, t->priv_nbytes);

    fixed_rng_init(&rng, t->coins, t->coins_nbytes);
    rv = cckem_encapsulate(pub, sizeof(ek), ek, sizeof(ss), ss, &rng.base);
    checkf(rv == 0, "%s: encapsulate -> %d", t->name, rv);
    check_bytes(t->name, ek, t->ct, t->ct_nbytes);
    check_bytes(t->name, ss, t->ss, 32);

    rv = cckem_decapsulate(full, t->ct_nbytes, t->ct, 32, ss2);
    checkf(rv == 0, "%s: decapsulate -> %d", t->name, rv);
    check_bytes(t->name, ss2, t->ss, 32);

    memcpy(bad_ek, t->ct, t->ct_nbytes);
    bad_ek[0] ^= 1;
    rv = cckem_decapsulate(full, t->ct_nbytes, bad_ek, 32, ss2);
    checkf(rv == 0 && memcmp(ss2, t->ss, 32) != 0,
           "%s: modified ciphertext is implicitly rejected", t->name);

    fixed_rng_init(&rng, t->seed, t->seed_nbytes);
    rv = cckem_generate_key_with_seed(full2, t->seed_nbytes, seed_out, &rng.base);
    checkf(rv == 0, "%s: generate_key_with_seed -> %d", t->name, rv);
    check_bytes(t->name, seed_out, t->seed, t->seed_nbytes);
    n = sizeof(pk2);
    cckem_export_pubkey(cckem_public_ctx(full2), &n, pk2);
    check_bytes(t->name, pk2, t->pk, t->pk_nbytes);

    rv = cckem_derive_key_from_seed(full, t->seed_nbytes - 1, t->seed, &rng.base);
    checkf(rv == CCERR_PARAMETER, "%s: short seed rejected -> %d", t->name, rv);
    rv = cckem_import_pubkey(info, t->pk_nbytes - 1, t->pk, pub);
    checkf(rv == CCERR_PARAMETER, "%s: short public key rejected -> %d", t->name, rv);
    rv = cckem_import_privkey(info, t->priv_nbytes - 1, priv, full2);
    checkf(rv == CCERR_PARAMETER, "%s: short private key rejected -> %d", t->name, rv);
    rv = cckem_encapsulate(pub, t->ct_nbytes - 1, ek, sizeof(ss), ss, &rng.base);
    checkf(rv == CCERR_PARAMETER, "%s: short ciphertext buffer rejected -> %d",
           t->name, rv);
    rv = cckem_decapsulate(full, t->ct_nbytes - 1, t->ct, sizeof(ss), ss);
    checkf(rv == CCERR_PARAMETER, "%s: short ciphertext rejected -> %d", t->name, rv);
}

#define KAT_NAME3(a, b, c) KAT_NAME3_(a, b, c)
#define KAT_NAME3_(a, b, c) a##_##b##_##c

#define KEM_KAT_ENTRY(_prefix_, _i_, _label_, _info_, _coins_, _pklen_, _privlen_, _ctlen_) \
    {                                                                               \
        .name = _label_ " " #_i_,                                                   \
        .info = (_info_),                                                           \
        .seed = KAT_NAME3(_prefix_, seed, _i_),                                     \
        .seed_nbytes = sizeof(KAT_NAME3(_prefix_, seed, _i_)),                     \
        .coins = KAT_NAME3(_prefix_, _coins_, _i_),                                \
        .coins_nbytes = sizeof(KAT_NAME3(_prefix_, _coins_, _i_)),                 \
        .pk = KAT_NAME3(_prefix_, pk, _i_),                                         \
        .pk_nbytes = (_pklen_),                                                     \
        .priv_nbytes = (_privlen_),                                                 \
        .ct = KAT_NAME3(_prefix_, ct, _i_),                                         \
        .ct_nbytes = (_ctlen_),                                                     \
        .ss = KAT_NAME3(_prefix_, ss, _i_),                                         \
    }

/* The ML-KEM KAT "msg" field is the 32-byte encapsulation randomness. */
#define MLKEM_KAT_ENTRY(_prefix_, _i_, _label_, _info_, _pklen_, _privlen_, _ctlen_) \
    {                                                                               \
        .name = _label_ " " #_i_,                                                   \
        .info = (_info_),                                                           \
        .seed = KAT_NAME3(_prefix_, seed, _i_),                                     \
        .seed_nbytes = sizeof(KAT_NAME3(_prefix_, seed, _i_)),                     \
        .coins = KAT_NAME3(_prefix_, msg, _i_),                                     \
        .coins_nbytes = sizeof(KAT_NAME3(_prefix_, msg, _i_)),                     \
        .pk = KAT_NAME3(_prefix_, pk, _i_),                                         \
        .pk_nbytes = (_pklen_),                                                     \
        .priv_nbytes = (_privlen_),                                                 \
        .ct = KAT_NAME3(_prefix_, ct, _i_),                                         \
        .ct_nbytes = (_ctlen_),                                                     \
        .ss = KAT_NAME3(_prefix_, ss, _i_),                                         \
    }

static const struct kem_kat kem_kats[] = {
    KEM_KAT_ENTRY(xwing_kat, 0, "X-Wing", cckem_xwing_mlkem768x25519,
                  eseed, 1216, 2464, 1120),
    KEM_KAT_ENTRY(xwing_kat, 1, "X-Wing", cckem_xwing_mlkem768x25519,
                  eseed, 1216, 2464, 1120),
    KEM_KAT_ENTRY(xwing_kat, 2, "X-Wing", cckem_xwing_mlkem768x25519,
                  eseed, 1216, 2464, 1120),
    MLKEM_KAT_ENTRY(mlkem768, 0, "ML-KEM-768", cckem_mlkem768,
                    1184, 2400, 1088),
    MLKEM_KAT_ENTRY(mlkem768, 1, "ML-KEM-768", cckem_mlkem768,
                    1184, 2400, 1088),
    MLKEM_KAT_ENTRY(mlkem1024, 0, "ML-KEM-1024", cckem_mlkem1024,
                    1568, 3168, 1568),
    MLKEM_KAT_ENTRY(mlkem1024, 1, "ML-KEM-1024", cckem_mlkem1024,
                    1568, 3168, 1568),
    KEM_KAT_ENTRY(kyber768, 0, "Kyber-768", cckem_kyber768,
                  coins, 1184, 2400, 1088),
    KEM_KAT_ENTRY(kyber768, 1, "Kyber-768", cckem_kyber768,
                  coins, 1184, 2400, 1088),
    KEM_KAT_ENTRY(kyber1024, 0, "Kyber-1024", cckem_kyber1024,
                  coins, 1568, 3168, 1568),
    KEM_KAT_ENTRY(kyber1024, 1, "Kyber-1024", cckem_kyber1024,
                  coins, 1568, 3168, 1568),
};

/* -------------------------------------------------------------------------
 * ML-DSA vectors
 * ------------------------------------------------------------------------- */

struct mldsa_kat {
    const char *name;
    const struct ccmldsa_params *(*params)(void);
    const uint8_t *seed;
    size_t seed_nbytes;
    const uint8_t *msg;
    size_t msg_nbytes;
    const uint8_t *ctx;
    size_t ctx_nbytes;
    const uint8_t *pk;
    size_t pk_nbytes;
    size_t priv_nbytes;
    size_t sig_nbytes;
    const uint8_t *sig;
};

static void test_mldsa_kat(const struct mldsa_kat *t)
{
    static const uint8_t context[] = "test_vectors";
    static const uint8_t wrong_context[] = "wrong_context";
    uint8_t pk[4096];
    uint8_t pk2[4096];
    uint8_t priv[8192];
    uint8_t priv2[8192];
    uint8_t sig[CCMLDSA87_SIGNATURE_NBYTES];
    uint8_t sig2[CCMLDSA87_SIGNATURE_NBYTES];
    uint8_t hash[64];
    uint8_t canary[CC_FAULT_CANARY_SIZE];
    struct fixed_rng rng;
    const struct ccmldsa_params *params = t->params();
    ccmldsa_full_ctx_decl(params, full);
    ccmldsa_full_ctx_decl(params, full2);
    ccmldsa_pub_ctx_decl(params, pub);
    size_t n;
    int rv;

    checkf(ccmldsa_pubkey_nbytes_params(params) == t->pk_nbytes,
           "%s: public key size", t->name);
    checkf(ccmldsa_privkey_nbytes_params(params) == t->priv_nbytes,
           "%s: private key size", t->name);
    checkf(ccmldsa_signature_nbytes_params(params) == t->sig_nbytes,
           "%s: signature size", t->name);
    checkf(ccmldsa_seed_nbytes_params(params) == t->seed_nbytes,
           "%s: seed size", t->name);

    ccmldsa_full_ctx_init(full, params);
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = ccmldsa_derive_key_from_seed(full, t->seed_nbytes, t->seed, &rng.base);
    checkf(rv == 0, "%s: derive_key_from_seed -> %d", t->name, rv);

    rv = ccmldsa_export_pubkey(ccmldsa_public_ctx(full), t->pk_nbytes, pk);
    checkf(rv == 0, "%s: export_pubkey -> %d", t->name, rv);
    check_bytes(t->name, pk, t->pk, t->pk_nbytes);

    rv = ccmldsa_export_privkey(full, t->priv_nbytes, priv);
    checkf(rv == 0, "%s: export_privkey -> %d", t->name, rv);

    ccmldsa_pub_ctx_init(pub, params);
    rv = ccmldsa_import_pubkey(params, t->pk_nbytes, pk, pub);
    checkf(rv == 0, "%s: import_pubkey -> %d", t->name, rv);
    rv = ccmldsa_export_pubkey(pub, t->pk_nbytes, pk2);
    checkf(rv == 0, "%s: imported public key round trip -> %d", t->name, rv);
    check_bytes(t->name, pk2, pk, t->pk_nbytes);

    ccmldsa_full_ctx_init(full2, params);
    rv = ccmldsa_import_privkey(params, t->priv_nbytes, priv, full2);
    checkf(rv == 0, "%s: import_privkey -> %d", t->name, rv);
    rv = ccmldsa_export_privkey(full2, t->priv_nbytes, priv2);
    checkf(rv == 0, "%s: imported private key round trip -> %d", t->name, rv);
    check_bytes(t->name, priv2, priv, t->priv_nbytes);

    /* Deterministic KAT signatures use an all-zero rnd value. */
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = ccmldsa_sign_with_context(full, t->sig_nbytes, sig,
                                   t->msg_nbytes, t->msg,
                                   t->ctx_nbytes, t->ctx, &rng.base);
    checkf(rv == 0, "%s: sign_with_context -> %d", t->name, rv);
    check_bytes(t->name, sig, t->sig, t->sig_nbytes);

    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes, sig, t->msg_nbytes, t->msg,
                                     t->ctx_nbytes, t->ctx);
    checkf(rv == CCERR_VALID_SIGNATURE, "%s: verify_with_context -> %d", t->name, rv);

    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes, sig, t->msg_nbytes - 1, t->msg,
                                     t->ctx_nbytes, t->ctx);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: wrong message rejected -> %d", t->name, rv);
    sig2[0] = sig[0];
    memcpy(sig2, sig, t->sig_nbytes);
    sig2[t->sig_nbytes / 2] ^= 1;
    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes, sig2, t->msg_nbytes, t->msg,
                                     t->ctx_nbytes, t->ctx);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: modified signature rejected -> %d", t->name, rv);
    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes - 1, sig, t->msg_nbytes, t->msg,
                                     t->ctx_nbytes, t->ctx);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: short signature rejected -> %d", t->name, rv);

    /* Context signing and fault canary behavior. */
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = ccmldsa_sign_with_context(full, t->sig_nbytes, sig,
                                   t->msg_nbytes, t->msg,
                                   sizeof(context), context, &rng.base);
    checkf(rv == 0, "%s: sign_with_context -> %d", t->name, rv);
    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes, sig,
                                     t->msg_nbytes, t->msg,
                                     sizeof(context), context);
    checkf(rv == CCERR_VALID_SIGNATURE,
           "%s: verify_with_context -> %d", t->name, rv);
    rv = ccmldsa_verify(pub, t->sig_nbytes, sig, t->msg_nbytes, t->msg);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: context mismatch rejected -> %d", t->name, rv);
    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes, sig,
                                     t->msg_nbytes, t->msg,
                                     sizeof(wrong_context), wrong_context);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: wrong context rejected -> %d", t->name, rv);

    memset(canary, 0xa5, sizeof(canary));
    rv = ccmldsa_verify_with_context_and_canary(pub, t->sig_nbytes, sig,
                                                t->msg_nbytes, t->msg,
                                                sizeof(context), context, canary);
    checkf(rv == CCERR_VALID_SIGNATURE &&
           CC_FAULT_CANARY_EQUAL(canary, CCMLDSA_FAULT_CANARY),
           "%s: success canary -> %d", t->name, rv);
    rv = ccmldsa_verify_with_context_and_canary(pub, t->sig_nbytes, sig,
                                                t->msg_nbytes, t->msg,
                                                sizeof(wrong_context), wrong_context,
                                                canary);
    checkf(rv == CCERR_INVALID_SIGNATURE &&
           CC_FAULT_CANARY_EQUAL(canary, zeros),
           "%s: failure clears canary -> %d", t->name, rv);

    /* HashML-DSA: prehash_with_context + sign_prehashed must verify. */
    n = ccmldsa_hash_nbytes_params(params);
    rv = ccmldsa_prehash_with_context(pub, n, hash, t->msg_nbytes, t->msg,
                                      sizeof(context), context);
    checkf(rv == 0, "%s: prehash_with_context -> %d", t->name, rv);
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = ccmldsa_sign_prehashed(full, t->sig_nbytes, sig2, n, hash, &rng.base);
    checkf(rv == 0, "%s: sign_prehashed -> %d", t->name, rv);
    rv = ccmldsa_verify_prehashed(pub, t->sig_nbytes, sig2, n, hash);
    checkf(rv == CCERR_VALID_SIGNATURE,
           "%s: verify_prehashed -> %d", t->name, rv);
    rv = ccmldsa_verify_with_context(pub, t->sig_nbytes, sig2,
                                     t->msg_nbytes, t->msg,
                                     sizeof(context), context);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: prehash signature domain separation -> %d", t->name, rv);

    memset(canary, 0xa5, sizeof(canary));
    rv = ccmldsa_verify_prehashed_with_canary(pub, t->sig_nbytes, sig2, n, hash,
                                              canary);
    checkf(rv == CCERR_VALID_SIGNATURE &&
           CC_FAULT_CANARY_EQUAL(canary, CCMLDSA_FAULT_CANARY),
           "%s: prehash success canary -> %d", t->name, rv);

    rv = ccmldsa_prehash(pub, n, hash, t->msg_nbytes, t->msg);
    checkf(rv == 0, "%s: prehash -> %d", t->name, rv);
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = ccmldsa_sign_prehashed(full, t->sig_nbytes, sig2, n, hash, &rng.base);
    checkf(rv == 0, "%s: sign_prehashed (no context) -> %d", t->name, rv);
    rv = ccmldsa_verify_prehashed(pub, t->sig_nbytes, sig2, n, hash);
    checkf(rv == CCERR_VALID_SIGNATURE,
           "%s: verify_prehashed (no context) -> %d", t->name, rv);
    rv = ccmldsa_verify(pub, t->sig_nbytes, sig2, t->msg_nbytes, t->msg);
    checkf(rv == CCERR_INVALID_SIGNATURE,
           "%s: pure verify rejects prehash signature -> %d", t->name, rv);

    rv = ccmldsa_sign_prehashed(full, t->sig_nbytes, sig2, n - 1, hash, &rng.base);
    checkf(rv == CCERR_PARAMETER, "%s: short hash rejected -> %d", t->name, rv);

    /* Seed round trip: derive the same key and sign identically. */
    ccmldsa_full_ctx_init(full2, params);
    rv = ccmldsa_derive_key_from_seed(full2, t->seed_nbytes, t->seed, &rng.base);
    checkf(rv == 0, "%s: seed round trip derive -> %d", t->name, rv);
    rv = ccmldsa_export_pubkey(ccmldsa_public_ctx(full2), t->pk_nbytes, pk2);
    checkf(rv == 0, "%s: seed round trip export -> %d", t->name, rv);
    check_bytes(t->name, pk2, pk, t->pk_nbytes);
    fixed_rng_init(&rng, zeros, sizeof(zeros));
    rv = ccmldsa_sign(full2, t->sig_nbytes, sig2, t->msg_nbytes, t->msg, &rng.base);
    checkf(rv == 0, "%s: seed round trip sign -> %d", t->name, rv);
    rv = ccmldsa_verify(pub, t->sig_nbytes, sig2, t->msg_nbytes, t->msg);
    checkf(rv == CCERR_VALID_SIGNATURE,
           "%s: seed round trip verify -> %d", t->name, rv);

    rv = ccmldsa_import_pubkey(params, t->pk_nbytes - 1, pk, pub);
    checkf(rv == CCERR_PARAMETER, "%s: short public key rejected -> %d",
           t->name, rv);
    rv = ccmldsa_import_privkey(params, t->priv_nbytes - 1, priv, full2);
    checkf(rv == CCERR_PARAMETER, "%s: short private key rejected -> %d",
           t->name, rv);
    rv = ccmldsa_derive_key_from_seed(full, t->seed_nbytes - 1, t->seed, &rng.base);
    checkf(rv == CCERR_PARAMETER, "%s: short seed rejected -> %d", t->name, rv);
}

#define MLDSA_KAT_ENTRY(_prefix_, _label_, _params_, _pklen_, _privlen_, _siglen_) \
    {                                                                               \
        .name = _label_,                                                            \
        .params = (_params_),                                                       \
        .seed = _prefix_##_seed_0,                                                  \
        .seed_nbytes = sizeof(_prefix_##_seed_0),                                   \
        .msg = _prefix_##_msg_0,                                                    \
        .msg_nbytes = sizeof(_prefix_##_msg_0),                                     \
        .ctx = _prefix_##_ctx_0,                                                    \
        .ctx_nbytes = sizeof(_prefix_##_ctx_0),                                     \
        .pk = _prefix_##_pk_0,                                                       \
        .pk_nbytes = (_pklen_),                                                     \
        .priv_nbytes = (_privlen_),                                                 \
        .sig_nbytes = (_siglen_),                                                   \
        .sig = _prefix_##_sig_0,                                                    \
    }

static const struct mldsa_kat mldsa_kats[] = {
    MLDSA_KAT_ENTRY(mldsa65, "ML-DSA-65 KAT 0", ccmldsa65,
                    1952, 4032, 3309),
    MLDSA_KAT_ENTRY(mldsa87, "ML-DSA-87 KAT 0", ccmldsa87,
                    2592, 4896, 4627),
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(kem_kats) / sizeof(kem_kats[0]); i++) {
        test_kem_kat(&kem_kats[i]);
    }
    for (i = 0; i < sizeof(mldsa_kats) / sizeof(mldsa_kats[0]); i++) {
        test_mldsa_kat(&mldsa_kats[i]);
    }

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
