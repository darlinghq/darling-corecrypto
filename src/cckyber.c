/*
 * Kyber (round 3) support through the corecrypto KEM interface.
 *
 * The polynomial/ring arithmetic comes from the CC0 PQClean clean
 * implementations of Kyber768 and Kyber1024 (src/pqc).
 */

#include "cckem_priv.h"
#include <corecrypto/cckyber.h>

int PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int PQCLEAN_KYBER768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static const struct cckem_info kyber768_info;
static const struct cckem_info kyber1024_info;

static int kyber_keygen_derand(const struct cckem_info *info,
                               uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    if (info == &kyber768_info) {
        return PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    }
    return PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
}

static int kyber_encaps_derand(const struct cckem_info *info,
                               const uint8_t *pk, uint8_t *ek, uint8_t *ss,
                               const uint8_t *random) {
    if (info == &kyber768_info) {
        return PQCLEAN_KYBER768_CLEAN_crypto_kem_enc_derand(ek, ss, pk, random);
    }
    return PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc_derand(ek, ss, pk, random);
}

static int kyber_decaps(const struct cckem_info *info,
                        const uint8_t *sk, const uint8_t *ek, uint8_t *ss) {
    if (info == &kyber768_info) {
        return PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(ss, ek, sk);
    }
    return PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(ss, ek, sk);
}

static const struct cckem_info kyber768_info = {
    .pubkey_nbytes = 1184,
    .privkey_nbytes = 2400,
    .ek_nbytes = 1088,
    .sk_nbytes = 32,
    .seed_nbytes = 32,
    .encaps_random_nbytes = 32,
    .keygen_derand = kyber_keygen_derand,
    .encaps_derand = kyber_encaps_derand,
    .decaps = kyber_decaps,
};

static const struct cckem_info kyber1024_info = {
    .pubkey_nbytes = 1568,
    .privkey_nbytes = 3168,
    .ek_nbytes = 1568,
    .sk_nbytes = 32,
    .seed_nbytes = 32,
    .encaps_random_nbytes = 32,
    .keygen_derand = kyber_keygen_derand,
    .encaps_derand = kyber_encaps_derand,
    .decaps = kyber_decaps,
};

const struct cckem_info *cckem_kyber768(void) {
    return &kyber768_info;
}

const struct cckem_info *cckem_kyber1024(void) {
    return &kyber1024_info;
}
