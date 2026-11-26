/*
 * ML-KEM (FIPS 203) support through the corecrypto KEM interface.
 *
 * The polynomial/ring arithmetic comes from the CC0 PQClean clean
 * implementations of ML-KEM-768 and ML-KEM-1024 (src/pqc).
 */

#include "cckem_priv.h"
#include <corecrypto/ccmlkem.h>

/* Declarations from the two PQClean ML-KEM backends.  Their params.h headers
 * use unprefixed Kyber constants, so they cannot be included together. */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static const struct cckem_info mlkem768_info;
static const struct cckem_info mlkem1024_info;

/* FIPS 203 Algorithm 7 (ML-KEM.KeyGen_internal) takes d || z, each 32 bytes.
 * The corecrypto seed is that 64-byte value. */
static int mlkem_keygen_derand(const struct cckem_info *info,
                               uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    if (info == &mlkem768_info) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    }
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
}

static int mlkem_encaps_derand(const struct cckem_info *info,
                               const uint8_t *pk, uint8_t *ek, uint8_t *ss,
                               const uint8_t *random) {
    if (info == &mlkem768_info) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ek, ss, pk, random);
    }
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ek, ss, pk, random);
}

static int mlkem_decaps(const struct cckem_info *info,
                        const uint8_t *sk, const uint8_t *ek, uint8_t *ss) {
    if (info == &mlkem768_info) {
        return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ek, sk);
    }
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ek, sk);
}

static const struct cckem_info mlkem768_info = {
    .pubkey_nbytes = CCMLKEM768_PUBKEY_NBYTES,
    .privkey_nbytes = CCMLKEM768_PRIVKEY_NBYTES,
    .ek_nbytes = 1088,
    .sk_nbytes = 32,
    .seed_nbytes = 64,
    .encaps_random_nbytes = 32,
    .keygen_derand = mlkem_keygen_derand,
    .encaps_derand = mlkem_encaps_derand,
    .decaps = mlkem_decaps,
};

static const struct cckem_info mlkem1024_info = {
    .pubkey_nbytes = CCMLKEM1024_PUBKEY_NBYTES,
    .privkey_nbytes = CCMLKEM1024_PRIVKEY_NBYTES,
    .ek_nbytes = 1568,
    .sk_nbytes = 32,
    .seed_nbytes = 64,
    .encaps_random_nbytes = 32,
    .keygen_derand = mlkem_keygen_derand,
    .encaps_derand = mlkem_encaps_derand,
    .decaps = mlkem_decaps,
};

const struct cckem_info *cckem_mlkem768(void) {
    return &mlkem768_info;
}

const struct cckem_info *cckem_mlkem1024(void) {
    return &mlkem1024_info;
}
