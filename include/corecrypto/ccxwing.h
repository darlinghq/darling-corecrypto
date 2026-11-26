/*
 *  ccxwing.h
 *  corecrypto
 *
 *  Public API declarations, compatible with the corecrypto X-Wing interface.
 */

#ifndef _CORECRYPTO_CCXWING_H_
#define _CORECRYPTO_CCXWING_H_

#include <corecrypto/cckem.h>
#include <corecrypto/ccmlkem.h>
#include <corecrypto/ccec25519.h>

CC_PTRCHECK_CAPABLE_HEADER()

/*! @function cckem_xwing_mlkem768x25519
    @abstract Return the `cckem_info` for X-Wing with ML-KEM-768 and X25519.
    See https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/
*/
const struct cckem_info *cckem_xwing_mlkem768x25519(void);

#define CCXWING_MLKEM768X25519_SEED_NBYTES 32
#define CCXWING_MLKEM768X25519_PUBKEY_NBYTES (CCMLKEM768_PUBKEY_NBYTES + sizeof(ccec25519pubkey))
#define CCXWING_MLKEM768X25519_FULLKEY_NBYTES CCMLKEM768_PUBKEY_NBYTES + sizeof(ccec25519pubkey) + CCMLKEM768_PRIVKEY_NBYTES + sizeof(ccec25519key) + CCXWING_MLKEM768X25519_SEED_NBYTES

#define CCXWING_MLKEM768X25519_PUBKEY_CTX_NBYTES (sizeof(struct cckem_pub_ctx) + CCXWING_MLKEM768X25519_PUBKEY_NBYTES)
#define CCXWING_MLKEM768X25519_FULLKEY_CTX_NBYTES (sizeof(struct cckem_full_ctx) + CCXWING_MLKEM768X25519_FULLKEY_NBYTES)

#define ccxwing_mlkem768x25519_full_ctx_decl(_name_) cc_ctx_decl(struct cckem_full_ctx, CCXWING_MLKEM768X25519_FULLKEY_CTX_NBYTES, _name_)
#define ccxwing_mlkem768x25519_full_ctx_clear(_name_) cc_memset(_name_, 0, CCXWING_MLKEM768X25519_FULLKEY_CTX_NBYTES)

#define ccxwing_mlkem768x25519_pub_ctx_decl(_name_) cc_ctx_decl(struct cckem_pub_ctx, CCXWING_MLKEM768X25519_PUBKEY_CTX_NBYTES, _name_)
#define ccxwing_mlkem768x25519_pub_ctx_clear(_name_) cc_memset(_name_, 0, CCXWING_MLKEM768X25519_PUBKEY_CTX_NBYTES)

#endif /* _CORECRYPTO_CCXWING_H_ */
