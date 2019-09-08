#!/usr/bin/env sh

# Check the link below to install watchman:
# https://facebook.github.io/watchman/docs/install.html
watchman-make -p 'src/**' 'tests/**' CMakeLists.txt --run ./run_tests.sh