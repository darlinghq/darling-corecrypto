# Darling-CoreCrypto

Rewrite of Apple CoreCrypto for the Darling project.

## Testing

Setting the CORECRYPTO_ENABLE_TESTS CMake option to ON as shown below will build CoreCrypto and the test suite
 for your native host instead of Darling. It has only been tested on Ubuntu 18.04 and OSX 10.14.

```
$ mkdir build
$ cd build
$ cmake -DCORECRYPTO_ENABLE_TESTS=ON ..
$ make
$ ./tests/test_corecrypto
```

### Continuous testing

The following command will watch for a any change in the CoreCrypto lib, CMake files or tests and will rebuild and run the test suite.

```
$ ./tests/watch.sh
```
