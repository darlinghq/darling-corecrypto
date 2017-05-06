project(darling-corecrypto)

add_compile_options(
	-nostdinc
	-Wno-return-type
)

add_definitions(
	-D_FILE_OFFSET_BITS=64
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(DYLIB_INSTALL_NAME "/usr/lib/system/libcorecrypto.dylib")
add_circular(corecrypto FAT
	SOURCES
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
		src/ccsha2.c
		src/cczp.c
		src/ccsha1.c
		src/ccrsa.c
		src/ccrng.c
		src/ccrc4.c
		src/ccn.c
		src/ccmode.c
		src/ccdes.c
		src/ccrsa_priv.c

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

install(TARGETS corecrypto DESTINATION libexec/darling/usr/lib/system)
