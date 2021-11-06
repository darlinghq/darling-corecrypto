set(TEST_SOURCES
	main.c
	cc_tests.c
	cc_priv_tests.c
	ccn_tests.c
	cczp_tests.c
	ccdigest_tests.c
	ccaes_tests.c
	ccdes_tests.c
)

add_custom_command(
	OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/test_data.h"
	COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate-test-data.py" ARGS "${CMAKE_CURRENT_BINARY_DIR}/test_data.h"
	DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/generate-test-data.py" # if the generation script changes, update the test data
)
add_custom_target(generate_test_data DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/test_data.h")

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/ctest
	"${CMAKE_CURRENT_BINARY_DIR}"
)

if (DARLING)
	add_darling_executable(test_corecrypto ${TEST_SOURCES})
	install(TARGETS test_corecrypto DESTINATION libexec/darling/usr/libexec)
else()
	add_executable(test_corecrypto ${TEST_SOURCES})
	target_link_libraries(test_corecrypto PRIVATE corecrypto)
endif()

add_dependencies(test_corecrypto generate_test_data)
