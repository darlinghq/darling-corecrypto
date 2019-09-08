# Darling-Corecrypto

Rewrite of Apple corecrypto for the darling project.

## Testing

Setting the CORECRYPTO_ENABLE_TESTS cmake option to ON as shown below will build corecrypoto and the test suite
 for your native host instead darling. It has only been tested on Ubuntu 18.04 and OSX 10.14.

```
$ mkdir build
$ cd build
$ cmake -DCORECRYPTO_ENABLE_TESTS=ON ..
$ make
$ ./tests/test_corecrypto
```

### Continuous testing

The following command will watch for a any change in the corecrypto lib, cmake files or tests and will rebuild and run the test suite.

```
$ ./watch.sh
```
