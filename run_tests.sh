#!/usr/bin/env sh

# clear the screen and the scroll buffer
printf "\033[2J\033[3J\033[1;1H"
# get into the build directory
mkdir -p build && cd build
# run cmake all the time, it's that fast
cmake -DCORECRYPTO_ENABLE_TESTS=ON -DCMAKE_RULE_MESSAGES=OFF ..
# build the lib and the tests
make -j8 --quiet
# run the tests
./tests/test_corecrypto