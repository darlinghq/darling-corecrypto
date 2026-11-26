// HKDF, as specified in RFC 5869, on top of cchmac.

#include <corecrypto/cchkdf.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/cc.h>
#include <corecrypto/cc_error.h>

// RFC 5869 section 2.2: PRK = HMAC-Hash(salt, IKM). A missing salt is a string
// of HashLen zeros.
int cchkdf_extract(const struct ccdigest_info *di, size_t saltLen, const void *salt,
	size_t keyDerivationKeyLen, const void *keyDerivationKey, void *prk) {
	if (saltLen == 0) {
		uint8_t zeros[di->output_size];
		cc_zero(di->output_size, zeros);
		cchmac(di, di->output_size, zeros, keyDerivationKeyLen, keyDerivationKey, prk);
	} else {
		cchmac(di, saltLen, salt, keyDerivationKeyLen, keyDerivationKey, prk);
	}
	return CCERR_OK;
}

// RFC 5869 section 2.3: T(0) is empty, T(i) = HMAC-Hash(PRK, T(i - 1) | info | i),
// and the output is the first L bytes of T(1) | T(2) | ... L is at most 255 * HashLen.
int cchkdf_expand(const struct ccdigest_info *di, size_t prkLen, const void *prk,
	size_t contextLen, const void *context, size_t derivedKeyLen, void *derivedKey) {
	const size_t hashLen = di->output_size;
	if (derivedKeyLen > 255 * hashLen)
		return CCERR_PARAMETER;

	cchmac_di_decl(di, keyed);
	cchmac_di_decl(di, hc);
	uint8_t t[hashLen];
	uint8_t *out = derivedKey;
	size_t done = 0;

	// the HMAC key is the same for every block, so the keyed state is set up once
	cchmac_init(di, keyed, prkLen, prk);

	for (uint8_t i = 1; done < derivedKeyLen; ++i) {
		cc_copy(cchmac_di_size(di), hc, keyed);
		if (i > 1)
			cchmac_update(di, hc, hashLen, t);
		cchmac_update(di, hc, contextLen, context);
		cchmac_update(di, hc, 1, &i);
		cchmac_final(di, hc, t);

		size_t n = derivedKeyLen - done < hashLen ? derivedKeyLen - done : hashLen;
		cc_copy(n, out + done, t);
		done += n;
	}

	cc_clear(sizeof(t), t);
	cchmac_di_clear(di, hc);
	cchmac_di_clear(di, keyed);
	return CCERR_OK;
}

int cchkdf(const struct ccdigest_info *di, size_t ikmLen, const void *ikm,
	size_t saltLen, const void *salt, size_t infoLen, const void *info,
	size_t dkLen, void *dk) {
	uint8_t prk[di->output_size];
	int status = cchkdf_extract(di, saltLen, salt, ikmLen, ikm, prk);
	if (status == CCERR_OK)
		status = cchkdf_expand(di, di->output_size, prk, infoLen, info, dkLen, dk);
	cc_clear(sizeof(prk), prk);
	return status;
}
