set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_ENV_PASSTHROUGH_UNTRACKED
    RAWFRAME_PREPARED_PERL_BIN
    RAWFRAME_PREPARED_NASM_DIR
    RAWFRAME_PREPARED_MSVC_BIN
    RAWFRAME_PREPARED_SDK_BIN)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_CMAKE_SYSTEM_NAME "")
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_LIST_DIR}/../toolchains/windows-x86_64.cmake")

# Compile and link flags belong to the chainload toolchain above, not here.
# vcpkg applies `VCPKG_C_FLAGS`, `VCPKG_CXX_FLAGS`, and `VCPKG_LINKER_FLAGS`
# inside its own toolchain, which a chainload replaces, so setting them in this
# triplet would look correct and reach nothing. This file previously carried
# `/EHs-c- /GR- -clang:-std=c++23`, and the measured GoogleTest compile line was
# `-std:c++17 ... /GR ... -W4 -WX`: C++17 with RTTI and exceptions enabled and a
# warning level taken from GoogleTest's own build files. Removing the three
# variables changes no produced byte; it removes a claim the build never made.
#
# The closure is deliberately built with upstream defaults. ADR-0008 governs
# first-party code, and forcing its flags onto third-party sources would be the
# wrong instrument in every case here: OpenSSL is C, GoogleTest is test-only and
# uses the features upstream tests against, and simdjson's exception policy is
# decided by the including translation unit rather than by its archive, which
# `dependency_authority.cpp` asserts at compile time.
