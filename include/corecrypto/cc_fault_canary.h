/*
 *  cc_fault_canary.h
 *  corecrypto
 *
 *  Public API declarations, compatible with the corecrypto fault canary
 *  interface.  Declarations only: no implementation from corecrypto.
 */

#ifndef _CORECRYPTO_CC_FAULT_CANARY_H_
#define _CORECRYPTO_CC_FAULT_CANARY_H_

#include <corecrypto/cc.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

#define CC_FAULT_CANARY_SIZE 16
typedef uint8_t cc_fault_canary_t[CC_FAULT_CANARY_SIZE];

extern const cc_fault_canary_t CCEC_FAULT_CANARY;
extern const cc_fault_canary_t CCRSA_PKCS1_FAULT_CANARY;
extern const cc_fault_canary_t CCRSA_PSS_FAULT_CANARY;
extern const cc_fault_canary_t CCMLDSA_FAULT_CANARY;

CC_END_DECLS

#define CC_FAULT_CANARY_MEMCPY(_dst_, _src_) cc_memcpy(_dst_, _src_, CC_FAULT_CANARY_SIZE)
#define CC_FAULT_CANARY_CLEAR(_name_) cc_memset(_name_, 0x00, CC_FAULT_CANARY_SIZE)
#define CC_FAULT_CANARY_EQUAL(_a_, _b_) (cc_cmp_safe(CC_FAULT_CANARY_SIZE, _a_, _b_) == 0)

#endif /* _CORECRYPTO_CC_FAULT_CANARY_H_ */
