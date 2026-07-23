cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_ARCHIVE RF_EXPECTED_ROOT)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1478 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")
rf_validate_archive_listing("${RF_ARCHIVE}" "${RF_EXPECTED_ROOT}")
message(STATUS "RF1479 archive listing fixture passed")

