set(TEST_SOURCES
	main.c
	cc_tests.c
	cc_priv_tests.c
	ccn_tests.c
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ctest)

add_darling_executable(test_corecrypto ${TEST_SOURCES})

install(TARGETS test_corecrypto DESTINATION libexec/darling/usr/libexec)
