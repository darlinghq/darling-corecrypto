#ifndef _CCRSA_PRIV_H_
#define _CCRSA_PRIV_H_

#include <corecrypto/ccrsa.h>
#include <corecrypto/cc_priv.h>

CC_NONNULL((1, 2, 4, 6))
int ccrsa_oaep_encode_parameter(const struct ccdigest_info* di,
                                struct ccrng_state *rng,
                                size_t r_size, cc_unit *r,
                                size_t message_len, const uint8_t *message,
                                size_t parameter_data_len, const uint8_t *parameter_data);

CC_INLINE CC_NONNULL((1, 2, 4, 6))
int ccrsa_oaep_encode(const struct ccdigest_info* di,
                      struct ccrng_state *rng,
                      size_t r_size, cc_unit *r,
                      size_t message_len, const uint8_t *message)
{
    return ccrsa_oaep_encode_parameter(di, rng, r_size, r, message_len, message, 0, NULL);
}

CC_INLINE CC_NONNULL((1, 2, 3, 5))
int ccrsa_oaep_decode(const struct ccdigest_info* di,
                      size_t *r_len, uint8_t *r,
                      size_t s_size, cc_unit* s)
{
    return ccrsa_oaep_decode_parameter(di, r_len, r, s_size, s, 0, NULL);
}

CC_NONNULL((1, 2, 3, 5))
int ccrsa_oaep_decode_parameter(const struct ccdigest_info* di,
                                size_t *r_len, uint8_t *r,
                                size_t s_size, cc_unit *s,
                                size_t parameter_data_len, const uint8_t *parameter_data);

#endif
