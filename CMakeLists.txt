cmake_minimum_required(VERSION 4.4.0)

project(rawframe LANGUAGES CXX)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are forbidden. Use a committed configure preset.")
endif()

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(RAWFRAME_BUILD_TESTS "Build Rawframe repository-tool tests" ON)
option(RAWFRAME_ENABLE_ANALYSIS "Run the pinned analyzer while compiling first-party source" OFF)

include(cmake/rawframe_compiler_policy.cmake)
include(cmake/rawframe_repository_authority.cmake)
include(cmake/rawframe_provider_policy.cmake)

rawframe_validate_repository_authority()
rawframe_define_compiler_policy()
rawframe_validate_provider_closure()

if(RAWFRAME_BUILD_TESTS)
    include(CTest)
    enable_testing()
    include(cmake/rawframe_repository_tests.cmake)
    rawframe_register_repository_tests()
endif()

add_subdirectory(tools/rf_evidence)
