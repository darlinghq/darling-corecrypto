set(TEST_SOURCES
	main.c
	cc_tests.c
	cc_priv_tests.c
	ccn_tests.c
	cczp_tests.c
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ctest)

if (DARLING)
	add_darling_executable(test_corecrypto ${TEST_SOURCES})
	install(TARGETS test_corecrypto DESTINATION libexec/darling/usr/libexec)
else()
	add_executable(test_corecrypto ${TEST_SOURCES})
	target_link_libraries(test_corecrypto PRIVATE corecrypto)
endif()
