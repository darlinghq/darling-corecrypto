#include <corecrypto/ccpad.h>
#include <corecrypto/cc.h>
#include <stdio.h>
#include <string.h>

size_t ccpad_cts1_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}

size_t ccpad_cts1_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}
size_t ccpad_cts2_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}

size_t ccpad_cts2_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}
size_t ccpad_cts3_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}

size_t ccpad_cts3_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}

/*
 * PKCS #7 padding (RFC 5652 section 6.3): the last block is filled with k
 * bytes of value k, 1 <= k <= block size, so a full block of padding follows
 * input whose length is a multiple of the block size.
 *
 * Decryption never reports bad padding (ccpad.h); ccpad_pkcs7_decode returns
 * the number of padding bytes to drop from the end of the last block.
 */

/* 1 if a < b, for a, b < 2^31 */
static inline uint32_t pad_less(uint32_t a, uint32_t b)
{
	return (a - b) >> 31;
}

/*
 * QUIRK: only the last byte k of the block is looked at: 1 <= k <= block size
 * drops k bytes whatever the other k - 1 bytes hold, any other k drops nothing.
 * ccpad.h describes dropping the whole block when the padding does not check
 * out; macOS does not do that.
 * Evidence: black-box observation (tier 2) of ccpad_pkcs7_decode and of
 * CCCrypt(kCCDecrypt, kCCOptionPKCS7Padding) on macOS 10.14.4 (x86_64) and
 * macOS 26.7.3 (x86_64), which agree: last byte 0, 17 or 255 -> 0;
 * "... 01 02" -> 2; "... 04 03 03" -> 3; "0f" followed by fifteen "10" -> 16.
 * Test: darling tests/src/commoncrypto_dh_modexp_pkcs7.c, test_quirk_pkcs7_padding_bytes_unchecked,
 * and tests/standalone/dh_modexp_pkcs7.c in this repository.
 * The value is computed without branches on the block contents.
 */
size_t ccpad_pkcs7_decode(const size_t block_size, const uint8_t* last_block)
{
	if (block_size == 0 || block_size > 255)
		return 0;

	const uint32_t size = (uint32_t)block_size;
	const uint32_t pad = last_block[size - 1];
	const uint32_t usable = (1 ^ pad_less(pad, 1)) & (1 ^ pad_less(size, pad));
	return (size_t)(pad & ((uint32_t)0 - usable));
}

/* bytes of input that go into full blocks, and the padded last block */
static size_t pad_last_block(size_t block_size, size_t nbytes, const void *in, uint8_t *block)
{
	const size_t full = nbytes - nbytes % block_size;
	const size_t rest = nbytes - full;

	memcpy(block, (const uint8_t *)in + full, rest);
	memset(block + rest, (int)(block_size - rest), block_size - rest);
	return full;
}

size_t ccpad_pkcs7_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                         size_t nbytes, const void *in, void *out)
{
	const size_t block_size = cccbc_block_size(cbc);
	if (block_size == 0 || block_size > 255)
		return 0;

	uint8_t block[block_size];
	const size_t full = pad_last_block(block_size, nbytes, in, block);

	if (full)
		cccbc_update(cbc, ctx, iv, full / block_size, in, out);
	cccbc_update(cbc, ctx, iv, 1, block, (uint8_t *)out + full);

	cc_clear(block_size, block);
	return full + block_size;
}

size_t ccpad_pkcs7_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx, cccbc_iv *iv,
                           size_t nbytes, const void *in, void *out)
{
	const size_t block_size = cccbc_block_size(cbc);
	if (block_size == 0 || nbytes == 0 || nbytes % block_size)
		return 0;

	cccbc_update(cbc, ctx, iv, nbytes / block_size, in, out);
	const uint8_t *last = (const uint8_t *)out + nbytes - block_size;
	return nbytes - ccpad_pkcs7_decode(block_size, last);
}

size_t ccpad_pkcs7_ecb_encrypt(const struct ccmode_ecb *ecb, ccecb_ctx *ctx,
                             size_t nbytes, const void *in, void *out)
{
	const size_t block_size = ccecb_block_size(ecb);
	if (block_size == 0 || block_size > 255)
		return 0;

	uint8_t block[block_size];
	const size_t full = pad_last_block(block_size, nbytes, in, block);

	if (full)
		ccecb_update(ecb, ctx, full / block_size, in, out);
	ccecb_update(ecb, ctx, 1, block, (uint8_t *)out + full);

	cc_clear(block_size, block);
	return full + block_size;
}

size_t ccpad_pkcs7_ecb_decrypt(const struct ccmode_ecb *ecb, ccecb_ctx *ecb_key,
                               size_t nbytes, const void *in, void *out)
{
	const size_t block_size = ccecb_block_size(ecb);
	if (block_size == 0 || nbytes == 0 || nbytes % block_size)
		return 0;

	ccecb_update(ecb, ecb_key, nbytes / block_size, in, out);
	const uint8_t *last = (const uint8_t *)out + nbytes - block_size;
	return nbytes - ccpad_pkcs7_decode(block_size, last);
}

size_t ccpad_xts_decrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
	return 8;
}

void ccpad_xts_encrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx, ccxts_tweak *tweak,
                       size_t nbytes, const void *in, void *out) {
	printf("DARLING CRYPTO STUB: %s\n", __PRETTY_FUNCTION__);
}
