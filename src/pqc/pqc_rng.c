#include "pqc_internal.h"
#include "randombytes.h"

#if defined(__GNUC__) || defined(__clang__)
#define PQC_THREAD_LOCAL __thread
#else
#define PQC_THREAD_LOCAL
#endif

static PQC_THREAD_LOCAL struct ccrng_state *s_rng;

void pqc_rng_set(struct ccrng_state *rng) {
    s_rng = rng;
}

int pqc_randombytes(uint8_t *out, size_t n) {
    struct ccrng_state *rng = s_rng;
    if (rng == NULL) {
        int error = 0;
        rng = ccrng(&error);
        if (rng == NULL || error != 0) {
            return -1;
        }
    }
    return ccrng_generate(rng, n, out) == 0 ? 0 : -1;
}

/* PQClean's randombytes() entry point. */
int PQCLEAN_randombytes(uint8_t *output, size_t n) {
    return pqc_randombytes(output, n);
}
