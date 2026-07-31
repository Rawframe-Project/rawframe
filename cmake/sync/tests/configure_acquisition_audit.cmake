cmake_minimum_required(VERSION 4.4.0)

# Mechanical audit of the two configure-lane properties rf-archcheck does not
# own: a find_package outside the locked dependency closure, and a committed
# preset that does not keep vcpkg manifest installation disabled.
#
# RF1538 (FetchContent and ExternalProject), RF1539 (file(DOWNLOAD)), and RF1540
# (source globbing) were retired under TASK-0010, owner-approved 2026-07-31.
# RA5003 and RA5001 replace them and enforce the same properties over a build
# lane derived by following include() and add_subdirectory() from the root build
# file, rather than over the list below. ADR-0077 requires a subsumed stage-0
# check to retire so that one property never has two check authorities.
#
# The list survives because RF1541 still needs it. It is a known weakness of
# RF1541, not of the retired checks: a build file added and not listed here is
# not audited for find_package. RA3005 covers dependency truth in the same
# files, so the gap is narrow, and closing it properly means giving
# rf-archcheck a find_package rule with its own authority citation.

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
    "tools/rf_archcheck/CMakeLists.txt"
    "tools/rf_archcheck/tests/CMakeLists.txt"
)

set(allowed_find_packages "simdjson" "OpenSSL" "GTest")

foreach(source IN LISTS build_lane_sources)
    set(path "${RF_REPOSITORY_ROOT}/${source}")
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "RF1537 audited build-lane source is missing: ${source}")
    endif()
    file(READ "${path}" contents LIMIT 1048576)

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

message(STATUS "RF1543 configure-lane find_package and preset audit passed")
