#include <corecrypto/ccdes.h>

const struct ccmode_ecb *ccdes_ecb_decrypt_mode(void) {
}

const struct ccmode_ecb *ccdes_ecb_encrypt_mode(void) {
}

const struct ccmode_cbc *ccdes_cbc_decrypt_mode(void) {
}

const struct ccmode_cbc *ccdes_cbc_encrypt_mode(void) {
}

const struct ccmode_cfb *ccdes_cfb_decrypt_mode(void) {
}

const struct ccmode_cfb *ccdes_cfb_encrypt_mode(void) {
}

const struct ccmode_cfb8 *ccdes_cfb8_decrypt_mode(void) {
}

const struct ccmode_cfb8 *ccdes_cfb8_encrypt_mode(void) {
}

const struct ccmode_ctr *ccdes_ctr_crypt_mode(void) {
}

const struct ccmode_ofb *ccdes_ofb_crypt_mode(void) {
}


const struct ccmode_ecb *ccdes3_ecb_decrypt_mode(void) {
}

const struct ccmode_ecb *ccdes3_ecb_encrypt_mode(void) {
}

const struct ccmode_cbc *ccdes3_cbc_decrypt_mode(void) {
}

const struct ccmode_cbc *ccdes3_cbc_encrypt_mode(void) {
}

const struct ccmode_cfb *ccdes3_cfb_decrypt_mode(void) {
}

const struct ccmode_cfb *ccdes3_cfb_encrypt_mode(void) {
}

const struct ccmode_cfb8 *ccdes3_cfb8_decrypt_mode(void) {
}

const struct ccmode_cfb8 *ccdes3_cfb8_encrypt_mode(void) {
}

const struct ccmode_ctr *ccdes3_ctr_crypt_mode(void) {
}

const struct ccmode_ofb *ccdes3_ofb_crypt_mode(void) {
}

int ccdes_key_is_weak(void *key, size_t  length) {
}

void ccdes_key_set_odd_parity(void *key, size_t length) {
}

uint32_t
ccdes_cbc_cksum(void *in, void *out, size_t length,
                void *key, size_t keylen, void *ivec) {
}

