#!/usr/bin/env python3
#
# Copyright (c) 2026 Darling Developers
#
# This file is part of Darling CoreCrypto.
#
# Darling is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Turns ECDSA signature verification vectors into one line per test for
# tests/standalone/ecdsa_vectors.c:
#
#   <id> <curve bits> <V|I|A> <X9.63 public key> <digest> <DER signature>
#
# V: must verify, I: must not verify, A: either (Wycheproof "acceptable").
# The digest is the full hash of the message; ccec_verify does the
# truncation to the order's bit length itself.
#
# Inputs (see tests/vectors/SOURCES):
#   *.json  Wycheproof EcdsaVerify files (ASN.1 DER signatures)
#   *.rsp   NIST CAVP FIPS 186-4 SigVer.rsp; binary curves are skipped
#
# Python 3 standard library only.

import hashlib
import json
import os
import re
import sys

CURVE_BITS = {
	"secp192r1": 192, "P-192": 192,
	"secp224r1": 224, "P-224": 224,
	"secp256r1": 256, "P-256": 256,
	"secp384r1": 384, "P-384": 384,
	"secp521r1": 521, "P-521": 521,
}

HASHES = {
	"SHA-1": "sha1",
	"SHA-224": "sha224",
	"SHA-256": "sha256",
	"SHA-384": "sha384",
	"SHA-512": "sha512",
}


def digest(hash_name, msg):
	return hashlib.new(HASHES[hash_name], msg).hexdigest()


def der_integer(value):
	body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
	return bytes([0x02]) + der_length(len(body)) + body


def der_length(length):
	if length < 0x80:
		return bytes([length])
	octets = length.to_bytes((length.bit_length() + 7) // 8, "big")
	return bytes([0x80 | len(octets)]) + octets


def der_signature(r, s):
	body = der_integer(r) + der_integer(s)
	return bytes([0x30]) + der_length(len(body)) + body


def wycheproof(path):
	name = os.path.basename(path)
	with open(path) as f:
		data = json.load(f)
	for group in data["testGroups"]:
		if group["type"] != "EcdsaVerify":
			continue
		curve = group["publicKey"]["curve"]
		if curve not in CURVE_BITS or group["sha"] not in HASHES:
			continue
		pub = group["publicKey"]["uncompressed"]
		for test in group["tests"]:
			expected = {"valid": "V", "invalid": "I", "acceptable": "A"}[test["result"]]
			print("%s:%d %d %s %s %s %s" % (
				name, test["tcId"], CURVE_BITS[curve], expected, pub,
				digest(group["sha"], bytes.fromhex(test["msg"])),
				test["sig"] or "-"))


def cavp(path):
	name = os.path.basename(path)
	section = None
	fields = {}
	count = 0
	with open(path) as f:
		for line in f:
			line = line.strip()
			m = re.match(r"^\[(.+),(SHA-\d+)\]$", line)
			if m:
				section = (m.group(1), m.group(2))
				continue
			m = re.match(r"^(\w+) = (.*)$", line)
			if not m or section is None:
				continue
			fields[m.group(1)] = m.group(2)
			if m.group(1) != "Result":
				continue
			count += 1
			curve, hash_name = section
			test = fields
			fields = {}
			if curve not in CURVE_BITS:
				continue
			size = (CURVE_BITS[curve] + 7) // 8
			pub = "04" + int(test["Qx"], 16).to_bytes(size, "big").hex() + int(test["Qy"], 16).to_bytes(size, "big").hex()
			sig = der_signature(int(test["R"], 16), int(test["S"], 16)).hex()
			expected = "V" if test["Result"].startswith("P") else "I"
			print("%s:%d %d %s %s %s %s" % (
				name, count, CURVE_BITS[curve], expected, pub,
				digest(hash_name, bytes.fromhex(test["Msg"])), sig))


def main():
	for path in sys.argv[1:]:
		if path.endswith(".json"):
			wycheproof(path)
		elif path.endswith(".rsp"):
			cavp(path)
		else:
			sys.exit("unknown vector file: " + path)


if __name__ == "__main__":
	main()
