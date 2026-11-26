/*
 *  ccmlkem.h
 *  corecrypto
 *
 *  Public API declarations, compatible with the corecrypto ML-KEM interface.
 */

#ifndef _CORECRYPTO_CCMLKEM_H_
#define _CORECRYPTO_CCMLKEM_H_

#include <corecrypto/cckem.h>

CC_PTRCHECK_CAPABLE_HEADER()
CC_BEGIN_DECLS

const struct cckem_info *cckem_mlkem768(void);
const struct cckem_info *cckem_mlkem1024(void);

#define CCMLKEM768_PUBKEY_NBYTES  1184
#define CCMLKEM768_PRIVKEY_NBYTES 2400

#define CCMLKEM768_PUBKEY_CTX_NBYTES (sizeof(struct cckem_pub_ctx) + CCMLKEM768_PUBKEY_NBYTES)
#define CCMLKEM768_FULLKEY_CTX_NBYTES (sizeof(struct cckem_full_ctx) + CCMLKEM768_PRIVKEY_NBYTES + CCMLKEM768_PUBKEY_NBYTES)

#define ccmlkem768_full_ctx_decl(_name_) cc_ctx_decl(struct cckem_full_ctx, CCMLKEM768_FULLKEY_CTX_NBYTES, _name_)
#define ccmlkem768_full_ctx_clear(_name_) cc_clear(CCMLKEM768_FULLKEY_CTX_NBYTES, _name_)

#define ccmlkem768_pub_ctx_decl(_name_) cc_ctx_decl(struct cckem_pub_ctx, CCMLKEM768_PUBKEY_CTX_NBYTES, _name_)
#define ccmlkem768_pub_ctx_clear(_name_) cc_clear(CCMLKEM768_PUBKEY_CTX_NBYTES, _name_)

#define CCMLKEM1024_PUBKEY_NBYTES  1568
#define CCMLKEM1024_PRIVKEY_NBYTES 3168

#define CCMLKEM1024_PUBKEY_CTX_NBYTES (sizeof(struct cckem_pub_ctx) + CCMLKEM1024_PUBKEY_NBYTES)
#define CCMLKEM1024_FULLKEY_CTX_NBYTES (sizeof(struct cckem_full_ctx) + CCMLKEM1024_PRIVKEY_NBYTES + CCMLKEM1024_PUBKEY_NBYTES)

#define ccmlkem1024_full_ctx_decl(_name_) cc_ctx_decl(struct cckem_full_ctx, CCMLKEM1024_FULLKEY_CTX_NBYTES, _name_)
#define ccmlkem1024_full_ctx_clear(_name_) cc_clear(CCMLKEM1024_FULLKEY_CTX_NBYTES, _name_)

#define ccmlkem1024_pub_ctx_decl(_name_) cc_ctx_decl(struct cckem_pub_ctx, CCMLKEM1024_PUBKEY_CTX_NBYTES, _name_)
#define ccmlkem1024_pub_ctx_clear(_name_) cc_clear(CCMLKEM1024_PUBKEY_CTX_NBYTES, _name_)

CC_END_DECLS

#endif /* _CORECRYPTO_CCMLKEM_H_ */
