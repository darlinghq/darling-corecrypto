#include <corecrypto/ccder.h>

CC_CONST
size_t ccder_sizeof(ccder_tag tag, size_t len) {
}

CC_PURE
size_t ccder_sizeof_implicit_integer(ccder_tag implicit_tag,
                                     cc_size n, const cc_unit *s) {
}

CC_PURE
size_t ccder_sizeof_implicit_octet_string(ccder_tag implicit_tag,
                                          cc_size n, const cc_unit *s) {
}

CC_CONST
size_t ccder_sizeof_implicit_raw_octet_string(ccder_tag implicit_tag,
                                              size_t s_size) {
}

CC_CONST
size_t ccder_sizeof_implicit_uint64(ccder_tag implicit_tag, uint64_t value) {
}

CC_PURE
size_t ccder_sizeof_integer(cc_size n, const cc_unit *s) {
}

CC_CONST
size_t ccder_sizeof_len(size_t len) {
}

CC_PURE
size_t ccder_sizeof_octet_string(cc_size n, const cc_unit *s) {
}

CC_PURE
size_t ccder_sizeof_oid(ccoid_t oid) {
}

CC_CONST
size_t ccder_sizeof_raw_octet_string(size_t s_size) {
}

CC_CONST
size_t ccder_sizeof_tag(ccder_tag tag) {
}

CC_CONST
size_t ccder_sizeof_uint64(uint64_t value) {
}

CC_NONNULL2
uint8_t *ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end) {
}

/* Returns a pointer to the start of the len field.  returns NULL if there
 is an encoding error. */
CC_NONNULL2
uint8_t *
ccder_encode_len(size_t len, const uint8_t *der, uint8_t *der_end) {
}

/* der_end should point to the first byte of the content of this der item. */
CC_NONNULL3
uint8_t *
ccder_encode_tl(ccder_tag tag, size_t len, const uint8_t *der, uint8_t *der_end) {
}

CC_PURE CC_NONNULL2
uint8_t *
ccder_encode_body_nocopy(size_t size, const uint8_t *der, uint8_t *der_end) {
}

/* Encode the tag and length of a constructed object.  der is the lower
   bound, der_end is one byte paste where we want to write the length and
   body_end is one byte past the end of the body of the der object we are
   encoding the tag and length of. */
CC_NONNULL((2, 3))
uint8_t *
ccder_encode_constructed_tl(ccder_tag tag, const uint8_t *body_end,
                            const uint8_t *der, uint8_t *der_end) {
}

/* Encodes oid into der and returns
 der + ccder_sizeof_oid(oid). */
CC_NONNULL_TU((1)) CC_NONNULL2
uint8_t *ccder_encode_oid(ccoid_t oid, const uint8_t *der, uint8_t *der_end) {
}

CC_NONNULL((3, 4))
uint8_t *ccder_encode_implicit_integer(ccder_tag implicit_tag,
                                       cc_size n, const cc_unit *s,
                                       const uint8_t *der, uint8_t *der_end) {
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_integer(cc_size n, const cc_unit *s,
                              const uint8_t *der, uint8_t *der_end) {
}

CC_NONNULL3
uint8_t *ccder_encode_implicit_uint64(ccder_tag implicit_tag,
                                      uint64_t value,
                                      const uint8_t *der, uint8_t *der_end) {
}

CC_NONNULL2
uint8_t *ccder_encode_uint64(uint64_t value,
                             const uint8_t *der, uint8_t *der_end) {
}

CC_NONNULL((3, 4))
uint8_t *ccder_encode_implicit_octet_string(ccder_tag implicit_tag,
                                            cc_size n, const cc_unit *s,
                                            const uint8_t *der,
                                            uint8_t *der_end) {
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_octet_string(cc_size n, const cc_unit *s,
                                   const uint8_t *der, uint8_t *der_end) {
}

CC_NONNULL((3, 4))
uint8_t *ccder_encode_implicit_raw_octet_string(ccder_tag implicit_tag,
                                                size_t s_size, const uint8_t *s,
                                                const uint8_t *der,
                                                uint8_t *der_end) {
}

CC_NONNULL((2, 3))
uint8_t *ccder_encode_raw_octet_string(size_t s_size, const uint8_t *s,
                                       const uint8_t *der, uint8_t *der_end) {
}

size_t ccder_encode_eckey_size(size_t priv_size, ccoid_t oid, size_t pub_size) {
}

CC_NONNULL2 CC_NONNULL5 CC_NONNULL6  CC_NONNULL7
uint8_t *ccder_encode_eckey(size_t priv_size, const uint8_t *priv_key,
                            ccoid_t oid,
                            size_t pub_size, const uint8_t *pub_key,
                            uint8_t *der, uint8_t *der_end) {
}

/* ccder_encode_body COPIES the body into the der.
   It's inefficient – especially when you already have to convert to get to
   the form for the body.
   see encode integer for the right way to unify conversion and insertion */
CC_NONNULL3
uint8_t *
ccder_encode_body(size_t size, const uint8_t* body,
                  const uint8_t *der, uint8_t *der_end) {
}

// MARK: ccder_decode_ functions.

/* Returns a pointer to the start of the length field, and returns the decoded tag in tag.
 returns NULL if there is a decoding error. */
CC_NONNULL((1, 3))
const uint8_t *ccder_decode_tag(ccder_tag *tagp, const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL((1, 3))
const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end) {
}

/* Returns a pointer to the start of the der object, and returns the length in len.
 returns NULL if there is a decoding error. */
CC_NONNULL((2, 4))
const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp,
                               const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL((2, 4))
const uint8_t *
ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end,
                            const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL((1, 3))
const uint8_t *
ccder_decode_sequence_tl(const uint8_t **body_end,
                         const uint8_t *der, const uint8_t *der_end) {
}

/*!
 @function   ccder_decode_uint_n
 @abstract   length in cc_unit of a der unsigned integer after skipping the leading zeroes

 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer
 @param      n          Output the number of cc_unit required to represent the number

 @result     First byte after the parsed integer or
        NULL if the integer is not valid (negative) or reach der_end when reading the integer
 */

CC_NONNULL((3))
const uint8_t *ccder_decode_uint_n(cc_size *n, 
                                 const uint8_t *der, const uint8_t *der_end) {
}

/*!
 @function   ccder_decode_uint
 @abstract   Represent in cc_unit a der unsigned integer after skipping the leading zeroes

 @param      der        Beginning of input DER buffer
 @param      der_end    End of input DER buffer
 @param      n          Number of cc_unit allocated for r
 @param      r          Allocated array of cc_unit to copy the integer into.

 @result     First byte after the parsed integer or
    NULL if the integer is not valid (negative)
            reach der_end when reading the integer
            n cc_unit is not enough to represent the integer
 */
CC_NONNULL((4))
const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r,
                                 const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL((3))
const uint8_t *ccder_decode_uint64(uint64_t* r,
                                   const uint8_t *der, const uint8_t *der_end) {
}

/* Decode SEQUENCE { r, s -- (unsigned)integer } in der into r and s.
   Returns NULL on decode errors, returns pointer just past the end of the
   sequence of integers otherwise. */
CC_NONNULL((2, 3, 5))
const uint8_t *ccder_decode_seqii(cc_size n, cc_unit *r, cc_unit *s,
                                  const uint8_t *der, const uint8_t *der_end) {
}
CC_NONNULL_TU((1)) CC_NONNULL((3))
const uint8_t *ccder_decode_oid(ccoid_t *oidp,
                                const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL((1,2,4))
const uint8_t *ccder_decode_bitstring(const uint8_t **bit_string,
                                size_t *bit_length,
                                const uint8_t *der, const uint8_t *der_end) {
}

CC_NONNULL_TU((4)) CC_NONNULL((1,2,3,5,6,8))
const uint8_t *ccder_decode_eckey(uint64_t *version,
                                  size_t *priv_size, const uint8_t **priv_key,
                                  ccoid_t *oid,
                                  size_t *pub_size, const uint8_t **pub_key,
                                  const uint8_t *der, const uint8_t *der_end) {
}
