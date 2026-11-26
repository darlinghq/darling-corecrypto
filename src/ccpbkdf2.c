// PBKDF2 with an HMAC PRF, as specified in RFC 8018 section 5.2.

#include <corecrypto/ccpbkdf2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>
#include <stdint.h>

int ccpbkdf2_hmac(const struct ccdigest_info *di,
                   size_t passwordLen, const void *password,
                   size_t saltLen, const void *salt,
                   size_t iterations,
                   size_t dkLen, void *dk) {
	const size_t hLen = di->output_size;

	// RFC 8018: the iteration count is a positive integer, and dkLen is at
	// most (2^32 - 1) * hLen
	if (iterations == 0)
		return CCERR_PARAMETER;
	if ((uint64_t)dkLen > (uint64_t)UINT32_MAX * hLen)
		return CCERR_PARAMETER;

	cchmac_di_decl(di, keyed);
	cchmac_di_decl(di, hc);
	uint8_t u[hLen];
	uint8_t t[hLen];
	uint8_t *out = dk;
	size_t done = 0;

	// the password is the HMAC key of every PRF call, so the keyed state is set up once
	cchmac_init(di, keyed, passwordLen, password);

	for (uint32_t i = 1; done < dkLen; ++i) {
		// U_1 = PRF(P, S || INT(i)), with INT(i) a big-endian 32-bit integer
		const uint8_t block_index[4] = { (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i };
		cc_copy(cchmac_di_size(di), hc, keyed);
		cchmac_update(di, hc, saltLen, salt);
		cchmac_update(di, hc, sizeof(block_index), block_index);
		cchmac_final(di, hc, u);
		cc_copy(hLen, t, u);

		// U_j = PRF(P, U_{j-1}), T_i = U_1 xor U_2 xor ... xor U_c
		for (size_t j = 1; j < iterations; ++j) {
			cc_copy(cchmac_di_size(di), hc, keyed);
			cchmac_update(di, hc, hLen, u);
			cchmac_final(di, hc, u);
			for (size_t k = 0; k < hLen; ++k)
				t[k] ^= u[k];
		}

		size_t n = dkLen - done < hLen ? dkLen - done : hLen;
		cc_copy(n, out + done, t);
		done += n;
	}

	cc_clear(sizeof(u), u);
	cc_clear(sizeof(t), t);
	cchmac_di_clear(di, hc);
	cchmac_di_clear(di, keyed);
	return CCERR_OK;
}
