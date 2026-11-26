/*
 *  cckyber.h
 *  corecrypto
 *
 *  Public API declarations, compatible with the corecrypto Kyber interface.
 */

#ifndef _CORECRYPTO_CCKYBER_H_
#define _CORECRYPTO_CCKYBER_H_

#include <corecrypto/cckem.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

const struct cckem_info *cckem_kyber768(void);
const struct cckem_info *cckem_kyber1024(void);

CC_END_DECLS

#endif /* _CORECRYPTO_CCKYBER_H_ */
