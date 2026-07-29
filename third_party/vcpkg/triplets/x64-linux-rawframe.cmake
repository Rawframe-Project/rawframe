set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_BUILD_TYPE release)
set(VCPKG_CMAKE_SYSTEM_NAME Linux)

# vcpkg runs an ELF RPATH rewrite after every Linux port unless a triplet says
# otherwise, and that rewrite acquires `patchelf` by download, which this
# offline lane forbids. The rewrite exists so that installed shared objects can
# locate their siblings at load time; this triplet builds every dependency
# statically, so it produces no shared object for the step to act on. Turning it
# off removes a network dependency instead of hiding one.
set(VCPKG_FIXUP_ELF_RPATH OFF)
set(VCPKG_CHAINLOAD_TOOLCHAIN_FILE
    "${CMAKE_CURRENT_LIST_DIR}/../toolchains/linux-x86_64.cmake")

# Compile and link flags belong to the chainload toolchain above, not here.
# vcpkg applies `VCPKG_C_FLAGS`, `VCPKG_CXX_FLAGS`, and `VCPKG_LINKER_FLAGS`
# inside its own toolchain, which a chainload replaces, so setting them in this
# triplet would look correct and reach nothing. Keeping one authority is the
# point; a second, silently ignored copy is worse than none.
