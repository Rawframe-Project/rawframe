cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_ARCHIVE RF_EXPECTED_ROOTS RF_DESTINATION)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1476 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")
file(REMOVE_RECURSE "${RF_DESTINATION}")
rf_extract_multi_root_quarantine("${RF_ARCHIVE}" "${RF_EXPECTED_ROOTS}" "${RF_DESTINATION}")
message(STATUS "RF1477 multi-root archive fixture passed")

