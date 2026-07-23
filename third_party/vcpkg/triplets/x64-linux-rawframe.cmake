set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

set(VCPKG_C_FLAGS "-Wall -Wextra -Wpedantic -Werror -stdlib=libc++")
set(VCPKG_CXX_FLAGS "-Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti -stdlib=libc++ -std=c++23")
set(VCPKG_LINKER_FLAGS "-stdlib=libc++ -fuse-ld=lld")
