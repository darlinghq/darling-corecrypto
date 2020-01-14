# Darling-CoreCrypto

Rewrite of Apple CoreCrypto for the Darling project.

## Testing

Setting the `ENABLE_TESTS` CMake option to ON as shown below will build CoreCrypto and the test suite
 for your native host instead of Darling. It has only been tested on Ubuntu 18.04 and OSX 10.14.

```
$ mkdir build
$ cd build
$ cmake -D_ENABLE_TESTS=ON ..
$ make
$ sudo make install
$ make lkm
$ sudo make lkm_install
$ darling shell
$ /usr/libexec/test_corecrypto
```
