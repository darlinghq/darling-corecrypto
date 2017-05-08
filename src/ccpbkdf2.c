#include <corecrypto/ccpbkdf2.h>

int ccpbkdf2_hmac(const struct ccdigest_info *di,
                   size_t passwordLen, const void *password,
                   size_t saltLen, const void *salt,
                   size_t iterations,
                   size_t dkLen, void *dk) {
	return 0;
}
