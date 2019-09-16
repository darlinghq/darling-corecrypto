cmake_minimum_required(VERSION 2.8)

project(darling-corecrypto C)

# User option to turn the corecrypto specific tests
option(CORECRYPTO_ENABLE_TESTS
	"Enable the compilation and running of corecrypto's unit tests" OFF)

# Test are built only if BUILD_TESTING && CORECRYPTO_ENABLE_TESTS are set to ON
include(CTest)
if (BUILD_TESTING AND CORECRYPTO_ENABLE_TESTS)
	set(BUILD_CORECRYPTO_TESTS ON)
else (BUILD_TESTING AND CORECRYPTO_ENABLE_TESTS)
	set(BUILD_CORECRYPTO_TESTS OFF)
endif (BUILD_TESTING AND CORECRYPTO_ENABLE_TESTS)

# Set endianess for test builds
if (BUILD_CORECRYPTO_TESTS)
	include (TestBigEndian)
	TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
	if(IS_BIG_ENDIAN)
		add_definitions(-D__BIG_ENDIAN__=1)
	else(IS_BIG_ENDIAN)
		add_definitions(-D__LITTLE_ENDIAN__=1)
	endif(IS_BIG_ENDIAN)
endif (BUILD_CORECRYPTO_TESTS)

# Set env dependent compile options
if (NOT BUILD_CORECRYPTO_TESTS)
	add_compile_options(
		-nostdinc
		-Wno-return-type
	)
else (NOT BUILD_CORECRYPTO_TESTS)
	add_compile_options(
		-Wno-return-type
	)
endif (NOT BUILD_CORECRYPTO_TESTS)

add_definitions(
	-D_FILE_OFFSET_BITS=64
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include
)


set(corecrypto_sources
		src/cc.c
		src/ccdigest.c
		src/ccmd2.c
		src/ccmd4.c
		src/ccmd5.c
		src/ccder.c
		src/ccec.c
		src/ccdh.c
		src/ccdh_gp.c
		src/ccaes.c
		src/ccsha2xx.c
		src/ccsha3xx.c
		src/cczp.c
		src/ccsha1.c
		src/ccrsa.c
		src/ccrng.c
		src/ccrng_system.c
		src/ccrc4.c
		src/ccn.c
		src/ccmode.c
		src/ccdes.c
		src/ccrsa_priv.c
		src/cccast.c
		src/ccrc2.c
		src/ccblowfish.c
		src/ccnistkdf.c
		src/ccz.c
		src/cccmac.c
		src/ccripemd.c
		src/cchkdf.c
		src/cchmac.c
		src/ccpad.c
		src/ccpbkdf2.c
		src/ccrc4.c
		src/ccansikdf.c
		src/ccecies.c
		src/ccrng_pbkdf2.c
)

if (NOT BUILD_CORECRYPTO_TESTS)
	set(DYLIB_INSTALL_NAME "/usr/lib/system/libcorecrypto.dylib")
	add_circular(corecrypto FAT
		SOURCES
			${corecrypto_sources}
		SIBLINGS
			system_dyld
			compiler_rt
			system_kernel
			platform
			system_malloc
			system_c
			system_blocks
			system_pthread
			macho
			libdispatch_shared
	)
	make_fat(corecrypto)
else (NOT BUILD_CORECRYPTO_TESTS)
	add_library(corecrypto
		SHARED
			${corecrypto_sources}
	)
endif (NOT BUILD_CORECRYPTO_TESTS)

if (NOT BUILD_CORECRYPTO_TESTS)
	install(TARGETS corecrypto DESTINATION libexec/darling/usr/lib/system)
else (NOT BUILD_CORECRYPTO_TESTS)
	enable_testing()
	include_directories(
		${CMAKE_CURRENT_SOURCE_DIR}/tests/include
	)
	add_subdirectory(external/ctest)
	add_subdirectory(tests)
endif (NOT BUILD_CORECRYPTO_TESTS)
