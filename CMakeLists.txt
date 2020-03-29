project(darling-corecrypto)

add_compile_options(
	-nostdinc
	-Wno-return-type
	-Werror
)

add_definitions(
	-DDEBUG
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
		src/ccec_projective_point.c
		src/ccec_points.c
		src/ccn_extra.c
		src/cczp_extra.c
)

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

install(TARGETS corecrypto DESTINATION libexec/darling/usr/lib/system)

if (ENABLE_TESTS)
	add_subdirectory(tests)
endif (ENABLE_TESTS)
