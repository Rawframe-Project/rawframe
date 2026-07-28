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

# This file configures every target built on this host, both the vcpkg
# dependency closure and the first-party tree, so it owns only what the platform
# closure requires. First-party warning level, language mode, exception and RTTI
# policy belong to `rawframe::compiler_policy`, which applies them per target;
# imposing them here would additionally apply them to third-party sources that
# this repository has no authority to remediate.
#
# The standard library is a platform closure decision rather than a style one,
# because a single link-compatible C++ ABI has to span dependencies and
# first-party code. It is the Linux counterpart of the single dynamic release
# CRT that the Windows lane selects. The admitted host installs the libstdc++
# runtime but no GCC development package, so libc++ from the locked LLVM tree is
# also the only standard library with headers present. `-stdlib=` is a C++
# selection that a C compile would reject as unused, so it stays off the C line.
set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")

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
