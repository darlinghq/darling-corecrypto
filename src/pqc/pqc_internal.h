/*
 * Glue between the corecrypto KEM/signature wrappers and the vendored CC0
 * post-quantum implementations.
 */

#ifndef _DARLING_PQC_INTERNAL_H_
#define _DARLING_PQC_INTERNAL_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccrng.h>

/* The vendored PQClean code obtains randomness through randombytes().  Point
 * that at the ccrng passed to the corecrypto entry point for the duration of
 * the call.  The value is thread-local so independent calls do not interfere. */
void pqc_rng_set(struct ccrng_state *rng);

/* Fill n bytes from the ccrng selected by pqc_rng_set(), or the global ccrng. */
int pqc_randombytes(uint8_t *out, size_t n);

#endif /* _DARLING_PQC_INTERNAL_H_ */
