// AES key wrap, as specified in RFC 3394 section 2.2 (the indexed form of
// the wrap and unwrap processes), with the initial value given by the caller.

#include <corecrypto/ccwrap_priv.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>
#include <stdint.h>
#include <string.h>

// RFC 3394 wraps at least two 64-bit blocks of key data
#define CCWRAP_MIN_SEMIBLOCKS 2

// The step counter t = n * j + i goes up to 6 * n and is xored into A as a
// big-endian 64-bit integer.
static void xor_counter(uint8_t a[CCWRAP_SEMIBLOCK], uint64_t t) {
	for (int k = CCWRAP_SEMIBLOCK - 1; k >= 0; --k) {
		a[k] ^= (uint8_t)t;
		t >>= 8;
	}
}

size_t ccwrap_wrapped_size(size_t unwrappedLen) {
	return unwrappedLen + CCWRAP_SEMIBLOCK;
}

size_t ccwrap_unwrapped_size(size_t wrappedLen) {
	return wrappedLen < CCWRAP_SEMIBLOCK ? 0 : wrappedLen - CCWRAP_SEMIBLOCK;
}

static int wrap(const struct ccmode_ecb* mode, ccecb_ctx* ctx, size_t unwrappedLen, const void* unwrappedKey, size_t* wrappedLen, void* wrappedKey, const void* iv) {
	if (mode->block_size != 2 * CCWRAP_SEMIBLOCK)
		return CCERR_PARAMETER;
	if (unwrappedLen % CCWRAP_SEMIBLOCK != 0 || unwrappedLen < CCWRAP_MIN_SEMIBLOCKS * CCWRAP_SEMIBLOCK)
		return CCERR_PARAMETER;
	if (*wrappedLen < ccwrap_wrapped_size(unwrappedLen))
		return CCERR_PARAMETER;

	const size_t n = unwrappedLen / CCWRAP_SEMIBLOCK;
	uint8_t* out = wrappedKey;
	uint8_t block[2 * CCWRAP_SEMIBLOCK];
	int status = CCERR_OK;

	// A = IV, R[1..n] = P[1..n]; R[i] lives at out + 8 * i, and A is kept in block
	cc_copy(CCWRAP_SEMIBLOCK, block, iv);
	memmove(out + CCWRAP_SEMIBLOCK, unwrappedKey, unwrappedLen);

	for (uint64_t j = 0; j <= 5; ++j) {
		for (size_t i = 1; i <= n; ++i) {
			// B = AES(K, A | R[i]); A = MSB(64, B) ^ t; R[i] = LSB(64, B)
			uint8_t* r = out + CCWRAP_SEMIBLOCK * i;
			cc_copy(CCWRAP_SEMIBLOCK, block + CCWRAP_SEMIBLOCK, r);
			if ((status = mode->ecb(ctx, 1, block, block)) != CCERR_OK)
				goto out;
			xor_counter(block, n * j + i);
			cc_copy(CCWRAP_SEMIBLOCK, r, block + CCWRAP_SEMIBLOCK);
		}
	}

	// C[0] = A
	cc_copy(CCWRAP_SEMIBLOCK, out, block);
	*wrappedLen = ccwrap_wrapped_size(unwrappedLen);

out:
	cc_clear(sizeof(block), block);
	if (status != CCERR_OK)
		cc_clear(ccwrap_wrapped_size(unwrappedLen), wrappedKey);
	return status;
}

static int unwrap(const struct ccmode_ecb* mode, ccecb_ctx* ctx, size_t wrappedLen, const void* wrappedKey, size_t* unwrappedLen, void* unwrappedKey, const void* iv) {
	if (mode->block_size != 2 * CCWRAP_SEMIBLOCK)
		return CCERR_PARAMETER;
	if (wrappedLen % CCWRAP_SEMIBLOCK != 0 || wrappedLen < (CCWRAP_MIN_SEMIBLOCKS + 1) * CCWRAP_SEMIBLOCK)
		return CCERR_PARAMETER;
	if (*unwrappedLen < ccwrap_unwrapped_size(wrappedLen))
		return CCERR_PARAMETER;

	const size_t n = wrappedLen / CCWRAP_SEMIBLOCK - 1;
	const uint8_t* in = wrappedKey;
	uint8_t* out = unwrappedKey;
	uint8_t block[2 * CCWRAP_SEMIBLOCK];
	int status = CCERR_OK;

	// A = C[0], R[1..n] = C[1..n]; R[i] lives at out + 8 * (i - 1)
	cc_copy(CCWRAP_SEMIBLOCK, block, in);
	memmove(out, in + CCWRAP_SEMIBLOCK, wrappedLen - CCWRAP_SEMIBLOCK);

	for (uint64_t j = 6; j-- > 0;) {
		for (size_t i = n; i >= 1; --i) {
			// B = AES-1(K, (A ^ t) | R[i]); A = MSB(64, B); R[i] = LSB(64, B)
			uint8_t* r = out + CCWRAP_SEMIBLOCK * (i - 1);
			xor_counter(block, n * j + i);
			cc_copy(CCWRAP_SEMIBLOCK, block + CCWRAP_SEMIBLOCK, r);
			if ((status = mode->ecb(ctx, 1, block, block)) != CCERR_OK)
				goto out;
			cc_copy(CCWRAP_SEMIBLOCK, r, block + CCWRAP_SEMIBLOCK);
		}
	}

	// the key data is only valid if A is the initial value
	if (cc_cmp_safe(CCWRAP_SEMIBLOCK, block, iv) != 0)
		status = CCERR_INTEGRITY;
	else
		*unwrappedLen = ccwrap_unwrapped_size(wrappedLen);

out:
	cc_clear(sizeof(block), block);
	if (status != CCERR_OK)
		cc_clear(ccwrap_unwrapped_size(wrappedLen), unwrappedKey);
	return status;
}

// On failure, the output length is 0: a failed CCSymmetricKeyUnwrap, which
// returns this length, reports a key length of 0 on macOS 26.7.3 (black-box
// observation through the public API). Wrapping does the same, so that a
// failure never reports output.
int ccwrap_auth_encrypt_withiv(const struct ccmode_ecb* mode, ccecb_ctx* ctx, size_t unwrappedLen, const void* unwrappedKey, size_t* wrappedLen, void* wrappedKey, const void* iv) {
	int status = wrap(mode, ctx, unwrappedLen, unwrappedKey, wrappedLen, wrappedKey, iv);
	if (status != CCERR_OK)
		*wrappedLen = 0;
	return status;
}

int ccwrap_auth_decrypt_withiv(const struct ccmode_ecb* mode, ccecb_ctx* ctx, size_t wrappedLen, const void* wrappedKey, size_t* unwrappedLen, void* unwrappedKey, const void* iv) {
	int status = unwrap(mode, ctx, wrappedLen, wrappedKey, unwrappedLen, unwrappedKey, iv);
	if (status != CCERR_OK)
		*unwrappedLen = 0;
	return status;
}
