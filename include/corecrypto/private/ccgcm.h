#ifndef CC_PRIVATE_CCGCM_H
#define CC_PRIVATE_CCGCM_H

#include <corecrypto/private/ccaes_extra.h>
#include <corecrypto/ccmode_impl.h>

//
// ~~~constants~~~
//

#define CCGCM_MODE_INITIALIZE 0
#define CCGCM_MODE_IV         1
#define CCGCM_MODE_AAD        2
#define CCGCM_MODE_CIPHERTEXT 3
#define CCGCM_MODE_FINALIZE   4

//
// ~~~typedefs~~~
//

typedef struct {
	// true if decrypting, false if encrypting
	bool decrypting;

	// initialize, IV, AAD, ciphertext, or finalize mode
	uint8_t mode;

	size_t key_len;
	const uint8_t* key;

	size_t total_iv_length;
	size_t total_cipher_length;
	size_t total_aad_length;

	uint8_t current_iv[12];

	// hash subkey
	ccaes_block_128_t hash_subkey;

	// initial counter block
	ccaes_block_128_t initial_cb;

	// cumulative hash block
	ccaes_block_128_t hash;

	// most recent block of data (IV, AAD, or ciphertext, depending on which mode we're in)
	ccaes_block_128_t cache;

	// current counter block
	// (used for ciphertext generation)
	ccaes_block_128_t cb;

	// cached result of processing the current counter block with the block cipher function
	ccaes_block_128_t processed_cb;
} ccgcm_state;

//
// ~~~function declarations~~~
//

// input_len should be a multiple of 16, otherwise you may receive unexpected results!
// (however the function will not error if it is not, you will simply receive possibly
// erroneous results)
ccaes_block_128_t ccgcm_ghash_128(const ccaes_block_128_t hash_subkey, const size_t input_len, const uint8_t* const input);

int ccgcm_gctr_128(const ccaes_block_cipher_function_t block_cipher_function, const size_t key_len, const uint8_t* const key, const ccaes_block_128_t icb, const size_t input_len, const uint8_t* const input, uint8_t* const output);

int ccgcm_internal_init(const struct ccmode_gcm* gcm, ccgcm_ctx* ctx, size_t key_len, const void* key);

int ccgcm_internal_set_iv(ccgcm_ctx* ctx, size_t iv_size, const void* iv);

int ccgcm_internal_gmac(ccgcm_ctx* ctx, size_t nbytes, const void* in);

int ccgcm_internal_gcm(ccgcm_ctx* ctx, size_t nbytes, const void* in, void* out);

int ccgcm_internal_finalize(ccgcm_ctx* key, size_t tag_size, void* tag);

int ccgcm_internal_reset(ccgcm_ctx* ctx);

void ccgcm_process_iv(ccgcm_state* ctx);

#endif // CC_PRIVATE_CCGCM_H
