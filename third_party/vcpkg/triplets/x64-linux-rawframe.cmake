set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_LIST_DIR}/../toolchains/linux-x86_64.cmake")

# Compile and link flags belong to the chainload toolchain above, not here.
# vcpkg applies `VCPKG_C_FLAGS`, `VCPKG_CXX_FLAGS`, and `VCPKG_LINKER_FLAGS`
# inside its own toolchain, which a chainload replaces, so setting them in this
# triplet would look correct and reach nothing. Keeping one authority is the
# point; a second, silently ignored copy is worse than none.
