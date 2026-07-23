cmake_minimum_required(VERSION 4.4.0)

# Mechanical audit: the configure/build lane must contain no acquisition
# mechanism. Maintained build-lane CMake sources may not use FetchContent,
# ExternalProject, file(DOWNLOAD), source globbing, or a find_package outside
# the locked dependency closure, and the committed presets must keep vcpkg
# manifest installation disabled.

if(NOT DEFINED RF_REPOSITORY_ROOT)
    message(FATAL_ERROR "RF1536 RF_REPOSITORY_ROOT is required")
endif()

set(build_lane_sources
    "CMakeLists.txt"
    "cmake/rawframe_compiler_policy.cmake"
    "cmake/rawframe_repository_authority.cmake"
    "cmake/rawframe_provider_policy.cmake"
    "cmake/rawframe_repository_tests.cmake"
    "tools/rf_evidence/CMakeLists.txt"
    "tools/rf_evidence/tests/CMakeLists.txt"
)

set(allowed_find_packages "simdjson" "OpenSSL" "GTest")

foreach(source IN LISTS build_lane_sources)
    set(path "${RF_REPOSITORY_ROOT}/${source}")
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "RF1537 audited build-lane source is missing: ${source}")
    endif()
    file(READ "${path}" contents LIMIT 1048576)

    string(CONCAT fetch_pattern "Fetch" "Content")
    string(CONCAT external_pattern "External" "Project")
    string(CONCAT download_pattern "file[ \t]*\\([ \t]*" "DOWNLOAD")
    string(CONCAT glob_pattern "file[ \t]*\\([ \t]*" "GLOB")
    if(contents MATCHES "${fetch_pattern}" OR contents MATCHES "${external_pattern}")
        message(FATAL_ERROR "RF1538 configure-time content acquisition found in ${source}")
    endif()
    if(contents MATCHES "${download_pattern}")
        message(FATAL_ERROR "RF1539 configure-time download found in ${source}")
    endif()
    if(contents MATCHES "${glob_pattern}")
        message(FATAL_ERROR "RF1540 source globbing found in build-lane source ${source}")
    endif()

    string(REGEX MATCHALL "find_package[ \t]*\\([ \t]*([A-Za-z0-9_]+)" find_calls "${contents}")
    foreach(find_call IN LISTS find_calls)
        string(REGEX REPLACE "find_package[ \t]*\\([ \t]*" "" package_name "${find_call}")
        list(FIND allowed_find_packages "${package_name}" allowed_index)
        if(allowed_index EQUAL -1)
            message(FATAL_ERROR "RF1541 find_package outside the locked closure in ${source}: ${package_name}")
        endif()
    endforeach()
endforeach()

file(READ "${RF_REPOSITORY_ROOT}/CMakePresets.json" presets LIMIT 1048576)
string(JSON preset_count LENGTH "${presets}" configurePresets)
math(EXPR preset_last "${preset_count} - 1")
foreach(index RANGE 0 ${preset_last})
    string(JSON preset_name GET "${presets}" configurePresets ${index} name)
    string(JSON manifest_install ERROR_VARIABLE manifest_error
        GET "${presets}" configurePresets ${index} cacheVariables VCPKG_MANIFEST_INSTALL)
    string(JSON inherits ERROR_VARIABLE inherits_error
        GET "${presets}" configurePresets ${index} inherits)
    if(NOT manifest_install STREQUAL "OFF" AND inherits_error)
        message(FATAL_ERROR
            "RF1542 configure preset '${preset_name}' does not disable vcpkg manifest installation")
    endif()
endforeach()

message(STATUS "RF1543 configure-lane acquisition audit passed")
