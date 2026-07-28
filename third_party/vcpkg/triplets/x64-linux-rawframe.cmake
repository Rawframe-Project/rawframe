set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_LIST_DIR}/../toolchains/linux-x86_64.cmake")

# `-stdlib=` selects a C++ standard library and is unused when compiling C, so
# `-Werror` turns it into a hard error there. It stays on the C++ and link lines,
# which is where the locked libc++ ABI is actually selected.
set(VCPKG_C_FLAGS "-Wall -Wextra -Wpedantic -Werror")
set(VCPKG_CXX_FLAGS "-Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti -stdlib=libc++ -std=c++23")
set(VCPKG_LINKER_FLAGS "-stdlib=libc++ -fuse-ld=lld")
