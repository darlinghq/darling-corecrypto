/*
 * X-Wing hybrid KEM (ML-KEM-768 + X25519), as specified in
 * draft-connolly-cfrg-xwing-kem-07.
 *
 * The X25519 field arithmetic is vendored from LibreSSL (ISC licensed) and
 * the ML-KEM-768 arithmetic from PQClean (CC0).
 */

#include "cckem_priv.h"
#include "fips202.h"
#include <corecrypto/ccxwing.h>
#include <string.h>

int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

void x25519_public_from_private(uint8_t out_public_value[32], const uint8_t private_key[32]);
void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

#define XWING_PK_M_NBYTES 1184
#define XWING_SK_M_NBYTES 2400
#define XWING_CT_M_NBYTES 1088
#define XWING_X_NBYTES 32
#define XWING_SEED_NBYTES 32

#define XWING_PUBKEY_NBYTES (XWING_PK_M_NBYTES + XWING_X_NBYTES)
#define XWING_PRIVKEY_NBYTES (XWING_SK_M_NBYTES + 2 * XWING_X_NBYTES)
#define XWING_EK_NBYTES (XWING_CT_M_NBYTES + XWING_X_NBYTES)

static const uint8_t xwing_label[6] = {0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c};

/* Combiner from draft-connolly-cfrg-xwing-kem-07 section 5.3. */
static void xwing_combiner(uint8_t ss[32],
                           const uint8_t ss_m[32], const uint8_t ss_x[32],
                           const uint8_t ct_x[32], const uint8_t pk_x[32]) {
    uint8_t buf[32 + 32 + 32 + 32 + sizeof(xwing_label)];
    memcpy(buf, ss_m, 32);
    memcpy(buf + 32, ss_x, 32);
    memcpy(buf + 64, ct_x, 32);
    memcpy(buf + 96, pk_x, 32);
    memcpy(buf + 128, xwing_label, sizeof(xwing_label));
    sha3_256(ss, buf, sizeof(buf));
    cc_clear(sizeof(buf), buf);
}

static void expand_decapsulation_key(const uint8_t seed[XWING_SEED_NBYTES],
                                     uint8_t sk_m[XWING_SK_M_NBYTES],
                                     uint8_t sk_x[XWING_X_NBYTES],
                                     uint8_t pk_m[XWING_PK_M_NBYTES],
                                     uint8_t pk_x[XWING_X_NBYTES]) {
    uint8_t expanded[96];
    shake256(expanded, sizeof(expanded), seed, XWING_SEED_NBYTES);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk_m, sk_m, expanded);
    memcpy(sk_x, expanded + 64, XWING_X_NBYTES);
    x25519_public_from_private(pk_x, sk_x);
    cc_clear(sizeof(expanded), expanded);
}

static int xwing_keygen_derand(const struct cckem_info *info,
                               uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    uint8_t sk_m[XWING_SK_M_NBYTES];
    uint8_t sk_x[XWING_X_NBYTES];
    uint8_t pk_m[XWING_PK_M_NBYTES];
    uint8_t pk_x[XWING_X_NBYTES];
    (void)info;

    expand_decapsulation_key(seed, sk_m, sk_x, pk_m, pk_x);
    memcpy(pk, pk_m, sizeof(pk_m));
    memcpy(pk + sizeof(pk_m), pk_x, sizeof(pk_x));
    memcpy(sk, sk_m, sizeof(sk_m));
    memcpy(sk + sizeof(sk_m), sk_x, sizeof(sk_x));
    memcpy(sk + sizeof(sk_m) + sizeof(sk_x), seed, XWING_SEED_NBYTES);

    cc_clear(sizeof(sk_m), sk_m);
    cc_clear(sizeof(sk_x), sk_x);
    return CCERR_OK;
}

static int xwing_encaps_derand(const struct cckem_info *info,
                               const uint8_t *pk, uint8_t *ek, uint8_t *ss,
                               const uint8_t *random) {
    const uint8_t *pk_x = pk + XWING_PK_M_NBYTES;
    uint8_t ek_x[XWING_X_NBYTES];
    uint8_t ss_x[XWING_X_NBYTES];
    uint8_t ss_m[32];
    (void)info;

    x25519_public_from_private(ek_x, random + XWING_SEED_NBYTES);
    x25519_scalar_mult(ss_x, random + XWING_SEED_NBYTES, pk_x);
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ek, ss_m, pk, random) != 0) {
        return CCERR_INTERNAL;
    }
    memcpy(ek + XWING_CT_M_NBYTES, ek_x, sizeof(ek_x));
    xwing_combiner(ss, ss_m, ss_x, ek_x, pk_x);

    cc_clear(sizeof(ss_m), ss_m);
    cc_clear(sizeof(ss_x), ss_x);
    cc_clear(sizeof(ek_x), ek_x);
    return CCERR_OK;
}

static int xwing_decaps(const struct cckem_info *info,
                        const uint8_t *sk, const uint8_t *ek, uint8_t *ss) {
    const uint8_t *sk_m = sk;
    const uint8_t *sk_x = sk + XWING_SK_M_NBYTES;
    const uint8_t *ct_x = ek + XWING_CT_M_NBYTES;
    uint8_t pk_x[XWING_X_NBYTES];
    uint8_t ss_x[XWING_X_NBYTES];
    uint8_t ss_m[32];
    (void)info;

    x25519_public_from_private(pk_x, sk_x);
    x25519_scalar_mult(ss_x, sk_x, ct_x);
    if (PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_m, ek, sk_m) != 0) {
        return CCERR_INTERNAL;
    }
    xwing_combiner(ss, ss_m, ss_x, ct_x, pk_x);

    cc_clear(sizeof(ss_m), ss_m);
    cc_clear(sizeof(ss_x), ss_x);
    cc_clear(sizeof(pk_x), pk_x);
    return CCERR_OK;
}

static const struct cckem_info xwing_info = {
    .pubkey_nbytes = XWING_PUBKEY_NBYTES,
    .privkey_nbytes = XWING_PRIVKEY_NBYTES,
    .ek_nbytes = XWING_EK_NBYTES,
    .sk_nbytes = 32,
    .seed_nbytes = XWING_SEED_NBYTES,
    .encaps_random_nbytes = 2 * XWING_SEED_NBYTES,
    .keygen_derand = xwing_keygen_derand,
    .encaps_derand = xwing_encaps_derand,
    .decaps = xwing_decaps,
};

const struct cckem_info *cckem_xwing_mlkem768x25519(void) {
    return &xwing_info;
}
