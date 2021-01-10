project(darling-corecrypto)

add_compile_options(
	-Wno-return-type
	-Werror
	-Wno-error=cpp
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
		src/ccgcm.c
		src/ccsrp.c
		src/ccwrap_priv.c
		src/cc_priv.c
		src/ccec25519.c
		src/cccbc.c
		src/ccccm.c
		src/cccfb.c
		src/cccfb8.c
		src/ccctr.c
		src/ccofb.c
		src/ccxts.c
		src/ccckg.c
)

if (DARLING)
	add_compile_options(
		-nostdinc
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

	target_link_options(corecrypto PRIVATE
		-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/scripts/exported-symbols.exp
	)

	add_darling_static_library(corecrypto_static FAT SOURCES $<TARGET_OBJECTS:corecrypto_obj>)

	install(TARGETS corecrypto DESTINATION libexec/darling/usr/lib/system)
else()
	add_library(corecrypto SHARED ${corecrypto_sources})
	# TODO: define list of exported symbols for non-Apple linkers
	# maybe we should just define CC_EXPORT and sprinkle that throughout our codebase
	#
	# building for non-Apple platforms is only used for quick testing at the moment,
	# so it doesn't matter that much if we have some unwanted exported symbols
endif()

if (ENABLE_TESTS)
	add_subdirectory(tests)
endif (ENABLE_TESTS)
