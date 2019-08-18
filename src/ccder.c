#include <corecrypto/ccder.h>
#include <stdio.h>

size_t ccder_sizeof(ccder_tag tag, size_t len) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_implicit_integer(ccder_tag implicit_tag,
                                     cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_implicit_octet_string(ccder_tag implicit_tag,
                                          cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_implicit_raw_octet_string(ccder_tag implicit_tag,
                                              size_t s_size) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_implicit_uint64(ccder_tag implicit_tag, uint64_t value) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_integer(cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_len(size_t len) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_octet_string(cc_size n, const cc_unit *s) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_oid(ccoid_t oid) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_raw_octet_string(size_t s_size) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_tag(ccder_tag tag) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_sizeof_uint64(uint64_t value) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *
ccder_encode_len(size_t len, const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *
ccder_encode_tl(ccder_tag tag, size_t len, const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *
ccder_encode_body_nocopy(size_t size, const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *
ccder_encode_constructed_tl(ccder_tag tag, const uint8_t *body_end,
                            const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_oid(ccoid_t oid, const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_implicit_integer(ccder_tag implicit_tag,
                                       cc_size n, const cc_unit *s,
                                       const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_integer(cc_size n, const cc_unit *s,
                              const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_implicit_uint64(ccder_tag implicit_tag,
                                      uint64_t value,
                                      const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_uint64(uint64_t value,
                             const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_implicit_octet_string(ccder_tag implicit_tag,
                                            cc_size n, const cc_unit *s,
                                            const uint8_t *der,
                                            uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_octet_string(cc_size n, const cc_unit *s,
                                   const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_implicit_raw_octet_string(ccder_tag implicit_tag,
                                                size_t s_size, const uint8_t *s,
                                                const uint8_t *der,
                                                uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_raw_octet_string(size_t s_size, const uint8_t *s,
                                       const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

size_t ccder_encode_eckey_size(size_t priv_size, ccoid_t oid, size_t pub_size) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *ccder_encode_eckey(size_t priv_size, const uint8_t *priv_key,
                            ccoid_t oid,
                            size_t pub_size, const uint8_t *pub_key,
                            uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

uint8_t *
ccder_encode_body(size_t size, const uint8_t* body,
                  const uint8_t *der, uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_tag(ccder_tag *tagp, const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp,
                               const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *
ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end,
                            const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *
ccder_decode_sequence_tl(const uint8_t **body_end,
                         const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_uint_n(cc_size *n, 
                                 const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r,
                                 const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_uint64(uint64_t* r,
                                   const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_seqii(cc_size n, cc_unit *r, cc_unit *s,
                                  const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
const uint8_t *ccder_decode_oid(ccoid_t *oidp,
                                const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_bitstring(const uint8_t **bit_string,
                                size_t *bit_length,
                                const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}

const uint8_t *ccder_decode_eckey(uint64_t *version,
                                  size_t *priv_size, const uint8_t **priv_key,
                                  ccoid_t *oid,
                                  size_t *pub_size, const uint8_t **pub_key,
                                  const uint8_t *der, const uint8_t *der_end) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
