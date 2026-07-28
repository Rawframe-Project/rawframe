cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH vcpkg_root)
cmake_path(GET vcpkg_root PARENT_PATH third_party_root)
cmake_path(GET third_party_root PARENT_PATH repository_root)
set(prepared_tools "${repository_root}/out/prepared/linux-x86_64/tools")

set(CMAKE_C_COMPILER "${prepared_tools}/llvm/bin/clang" CACHE FILEPATH "" FORCE)
set(CMAKE_CXX_COMPILER "${prepared_tools}/llvm/bin/clang++" CACHE FILEPATH "" FORCE)
set(CMAKE_LINKER "${prepared_tools}/llvm/bin/ld.lld" CACHE FILEPATH "" FORCE)
set(CMAKE_AR "${prepared_tools}/llvm/bin/llvm-ar" CACHE FILEPATH "" FORCE)
set(CMAKE_RANLIB "${prepared_tools}/llvm/bin/llvm-ranlib" CACHE FILEPATH "" FORCE)
set(CMAKE_MAKE_PROGRAM "${prepared_tools}/ninja/ninja" CACHE FILEPATH "" FORCE)

# Selecting a chainload toolchain replaces vcpkg's own toolchain rather than
# adding to it, so `VCPKG_C_FLAGS`, `VCPKG_CXX_FLAGS`, and `VCPKG_LINKER_FLAGS`
# from the triplet never reach the compiler. The flags therefore live here,
# where the compiler identity is already decided, so one file owns the whole
# Linux compile and link configuration instead of two that silently disagree.
#
# `-stdlib=` is a C++ selection and is unused when compiling C, where `-Werror`
# turns an unused argument into a hard failure, so it stays off the C line.
set(CMAKE_C_FLAGS_INIT "-Wall -Wextra -Wpedantic -Werror")
set(CMAKE_CXX_FLAGS_INIT
    "-Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti -stdlib=libc++ -std=c++23")

# The admitted host installs no binutils and no GCC development packages, so
# the driver has neither `ld` nor `crtbegin.o`/`libgcc.a` to fall back on. Every
# piece of that closure is instead taken from the locked LLVM tree: `ld.lld` as
# the linker, compiler-rt as the builtins runtime, and libunwind plus libc++ as
# the C++ runtime. This is the intended configuration rather than a workaround,
# because it keeps the toolchain closure inside the artifacts the lock verifies.
set(rf_linux_link_flags
    "-fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -stdlib=libc++")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${rf_linux_link_flags}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${rf_linux_link_flags}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${rf_linux_link_flags}")
