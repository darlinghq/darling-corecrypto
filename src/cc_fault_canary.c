#include <corecrypto/cc_fault_canary.h>

/* Fixed, algorithm-specific canary values.  Their contents are opaque to
 * callers; only equality against the exported constant matters. */
const cc_fault_canary_t CCEC_FAULT_CANARY = {
    'C', 'C', 'E', 'C', '_', 'C', 'A', 'N', 'A', 'R', 'Y', '!', '!', '!', '!', '!',
};
const cc_fault_canary_t CCRSA_PKCS1_FAULT_CANARY = {
    'P', 'K', 'C', 'S', '1', '_', 'C', 'A', 'N', 'A', 'R', 'Y', '!', '!', '!', '!',
};
const cc_fault_canary_t CCRSA_PSS_FAULT_CANARY = {
    'R', 'S', 'A', 'P', 'S', 'S', '_', 'C', 'A', 'N', 'A', 'R', 'Y', '!', '!', '!',
};
const cc_fault_canary_t CCMLDSA_FAULT_CANARY = {
    'M', 'L', 'D', 'S', 'A', '_', 'C', 'A', 'N', 'A', 'R', 'Y', '!', '!', '!', '!',
};
