# Darling-CoreCrypto

Rewrite of Apple CoreCrypto for the Darling project.

## Post-quantum support

The library also provides Apple-compatible interfaces for the NIST
post-quantum algorithms:

- **ML-KEM** (`ccmlkem.h`, `cckem.h`): ML-KEM-768 and ML-KEM-1024.
- **ML-DSA** (`ccmldsa.h`): ML-DSA-65 and ML-DSA-87, including context strings,
  HashML-DSA prehashing, import/export, and fault canaries.
- **X-Wing** (`ccxwing.h`): the hybrid ML-KEM-768 + X25519 KEM.
- **Kyber** (`cckyber.h`): legacy Kyber-768 and Kyber-1024, for compatibility
  with older callers.

The portable C backends are vendored under `src/pqc/` from PQClean (CC0) and
are documented in `THIRD_PARTY_NOTICES.md`. No Apple corecrypto source was
used for these implementations.

## Testing

Setting the `ENABLE_TESTS` CMake option to ON as shown below will build CoreCrypto and the test suite
 for your native host instead of Darling. It has only been tested on Ubuntu 18.04 and OSX 10.14.

We use Python (either 2 or 3) with the [`cryptography`](https://pypi.org/project/cryptography/) module to generate some of our test data, so make sure you have those installed before building.

```
$ mkdir build
$ cd build
$ cmake -DENABLE_TESTS=ON ..
$ make
$ ctest --output-on-failure   # PQC KATs and FIPS 202 backend tests
$ sudo make install
$ make lkm
$ sudo make lkm_install
$ darling shell
$ /usr/libexec/test_corecrypto
```
