project(darling-corecrypto)

add_compile_options(
	-nostdinc
)
add_definitions(
	-D_FILE_OFFSET_BITS=64
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

set(DYLIB_INSTALL_NAME "/usr/lib/system/libcorecrypto.dylib")
add_darling_library(corecrypto SHARED
		src/cc.c
		src/ccdigest.c
		src/ccmd2.c
		src/ccmd4.c
		src/ccmd5.c
		src/ccder.c
)
target_link_libraries(corecrypto PRIVATE
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
