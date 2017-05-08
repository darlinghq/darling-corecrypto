#include <corecrypto/ccsha1.h>

const uint32_t ccsha1_initial_state[5] = {
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
};

const struct ccdigest_info *ccsha1_di(void) {
}

void ccsha1_final(const struct ccdigest_info *di, ccdigest_ctx_t arg2,
                  unsigned char *digest) {
}

