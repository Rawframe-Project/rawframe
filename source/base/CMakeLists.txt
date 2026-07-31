# The zero-dependency leaf of the module graph.
#
# `module.json` is the architecture authority and this file is mechanics, per
# ADR-0004. It links exactly one thing, `rawframe::compiler_policy`, which is not
# a module: it is the pinned toolchain contract plus the `RAWFRAME_ASSERTIONS`
# projection `assert.h` reads. The manifest declares zero dependency edges and
# this file adds none, which is the property `rf-archcheck` RA3004 checks.

add_library(rawframe_base STATIC)
add_library(rawframe::base ALIAS rawframe_base)
target_sources(rawframe_base PRIVATE
    src/fatal.cpp
)
target_include_directories(rawframe_base PUBLIC include)
target_link_libraries(rawframe_base PUBLIC rawframe::compiler_policy)
set_target_properties(rawframe_base PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

if(RAWFRAME_BUILD_TESTS)
    find_package(GTest 1.17.0 EXACT CONFIG REQUIRED)
    add_subdirectory(tests)
endif()

if(RAWFRAME_ENABLE_ANALYSIS)
    if(NOT DEFINED RAWFRAME_CLANG_FORMAT_EXECUTABLE OR
       NOT EXISTS "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}")
        message(FATAL_ERROR "RF1121 the preset's locked clang-format executable is absent")
    endif()
    # The two negative-compile fixtures are maintained sources and are formatted
    # like every other one. They are absent from this list only if they are
    # absent from the repository, which the inventory test would catch.
    set(rawframe_base_maintained_sources
        include/rawframe/base/assert.h
        include/rawframe/base/bits128.h
        include/rawframe/base/bytes.h
        include/rawframe/base/fatal.h
        include/rawframe/base/platform.h
        src/fatal.cpp
        tests/allocation_observer.cpp
        tests/allocation_observer.h
        tests/assert_test.cpp
        tests/assertion_side_effect_lint_test.cpp
        tests/bits128_test.cpp
        tests/bytes_test.cpp
        tests/fatal_test.cpp
        tests/link_probe.cpp
        tests/negative/shipping_assertion_names_nothing.cpp
        tests/negative/unsupported_architecture.cpp
        tests/negative/unsupported_compiler.cpp
        tests/public_surface_test.cpp
        tests/single_header/assert_alone.cpp
        tests/single_header/bits128_alone.cpp
        tests/single_header/bytes_alone.cpp
        tests/single_header/fatal_alone.cpp
        tests/single_header/platform_alone.cpp
    )
    add_custom_target(rawframe_base_format_check ALL
        COMMAND "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}" --style=file --dry-run --Werror
            ${rawframe_base_maintained_sources}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Checking rawframe.base formatting against the repository .clang-format"
        VERBATIM)
endif()
