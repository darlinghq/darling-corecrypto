#ifndef _CCHKDF_H_
#define _CCHKDF_H_

#include <corecrypto/ccdigest.h>

// This is literally it
int cchkdf(const struct ccdigest_info *di, size_t ikmLen, const void *ikm,
	size_t saltLen, const void *salt, size_t infoLen, const void *info,
	size_t dkLen, void *dk);

#endif
