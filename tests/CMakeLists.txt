set(TEST_SOURCES
	main.c
	cc_tests.c
	cc_priv_tests.c
)

add_executable(test_corecrypto ${TEST_SOURCES})

target_link_libraries(test_corecrypto ctest corecrypto)

add_test(TestCorecrypto test_corecrypto)
