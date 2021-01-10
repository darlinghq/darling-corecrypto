#!/usr/bin/env python

import sys
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes

CC_SOURCE_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

AES_BLOCK_BITS = algorithms.AES.block_size
AES_BLOCK_BYTES = AES_BLOCK_BITS // 8
AES_KEY_BITS = [128, 192, 256]
GCM_IV_BITS = 96
GCM_IV_BYTES = GCM_IV_BITS // 8

# how many blocks to generate for the plaintext
PLAINTEXT_BLOCK_COUNT = 1

DIGEST_ALGORITHMS = [
	('sha1', hashes.SHA1()),
	('sha224', hashes.SHA224()),
	('sha256', hashes.SHA256()),
	('sha384', hashes.SHA384()),
	('sha512', hashes.SHA512()),
	('md5', hashes.MD5()),
]

# how many bytes to generate for the digest input data
DIGEST_INPUT_DATA_LENGTH = 256 # random cool number

# adapted from https://stackoverflow.com/a/53808695/6620880
def to_padded_hex(value, hex_digits=2):
	return '0x{0:0{1}x}'.format(value if isinstance(value, int) else ord(value), hex_digits)

def to_c_array(array_name, values, array_type='uint8_t', formatter=to_padded_hex, column_count=8, static=True):
	values = [formatter(v) for v in values]
	rows = [values[i:i + column_count] for i in range(0, len(values), column_count)]
	body = ',\n\t'.join([', '.join(r) for r in rows])
	return '{}{} {}[] = {{\n\t{},\n}};\n'.format('static ' if static else '', array_type, array_name, body)

def generate_aes_data():
	result = str()
	plaintext = os.urandom(PLAINTEXT_BLOCK_COUNT * AES_BLOCK_BYTES)

	result += '//\n' + '// AES\n' + '//\n'

	result += to_c_array('ccaes_plaintext_block', plaintext)

	for key_bits in AES_KEY_BITS:
		key = os.urandom(key_bits // 8)
		alg = algorithms.AES(key)

		result += '\n'

		result += '//\n' + '// AES-' + str(key_bits) + '\n' + '//\n'

		result += to_c_array('ccaes_' + str(key_bits) + '_key', key)

		result += '\n'

		result += '//\n' + '// AES-' + str(key_bits) + '-ECB\n' + '//\n'

		ecb = Cipher(alg, modes.ECB(), default_backend())
		enc = ecb.encryptor()
		result += to_c_array('ccaes_' + str(key_bits) + '_ecb_ciphertext', enc.update(plaintext) + enc.finalize())

		result += '\n'

		result += '//\n' + '// AES-' + str(key_bits) + '-CBC\n' + '//\n'

		cbc_iv = os.urandom(AES_BLOCK_BYTES)
		result += to_c_array('ccaes_' + str(key_bits) + '_cbc_iv', cbc_iv)
		cbc = Cipher(alg, modes.CBC(cbc_iv), default_backend())
		enc = cbc.encryptor()
		result += to_c_array('ccaes_' + str(key_bits) + '_cbc_ciphertext', enc.update(plaintext) + enc.finalize())

		result += '\n'

		result += '//\n' + '// AES-' + str(key_bits) + '-GCM\n' + '//\n'

		gcm_iv = os.urandom(GCM_IV_BYTES)
		result += to_c_array('ccaes_' + str(key_bits) + '_gcm_iv', gcm_iv)
		gcm = Cipher(alg, modes.GCM(gcm_iv), default_backend())
		enc = gcm.encryptor()
		result += to_c_array('ccaes_' + str(key_bits) + '_gcm_ciphertext', enc.update(plaintext) + enc.finalize())
		result += to_c_array('ccaes_' + str(key_bits) + '_gcm_tag', enc.tag)

	return result

def generate_digest_data():
	result = str()
	input_data = os.urandom(DIGEST_INPUT_DATA_LENGTH)

	result += '//\n' + '// Digests\n' + '//\n'

	result += to_c_array('ccdigest_input_data', input_data)

	for (name, alg) in DIGEST_ALGORITHMS:
		result += '\n'
		digest = hashes.Hash(alg, default_backend())
		result += '//\n' + '// Digest::' + name + '\n' + '//\n'
		digest.update(input_data)
		result += to_c_array('ccdigest_' + name + '_hash', digest.finalize())

	return result

output_string = str()

output_string += '#ifndef CC_TESTS_TEST_DATA_H\n'
output_string += '#define CC_TESTS_TEST_DATA_H\n\n'
output_string += '#include <stdint.h>\n\n'

output_string += generate_aes_data() + '\n'
output_string += generate_digest_data() + '\n'

output_string += '#endif // CC_TESTS_TEST_DATA_H\n'

output_path = os.path.join(CC_SOURCE_ROOT, 'tests/test_data.h')

if len(sys.argv) > 1:
	output_path = os.path.join(os.curdir, sys.argv[1])

output_file = open(output_path, 'w')
output_file.write(output_string)
