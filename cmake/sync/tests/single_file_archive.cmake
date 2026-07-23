cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_ARCHIVE RF_EXPECTED_FILE RF_EXPECTED_BYTES
                          RF_EXPECTED_SHA256 RF_DESTINATION)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1484 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")
file(REMOVE_RECURSE "${RF_DESTINATION}")
rf_extract_single_file_archive(
    "${RF_ARCHIVE}" "${RF_EXPECTED_FILE}" "${RF_EXPECTED_BYTES}" "${RF_EXPECTED_SHA256}"
    "${RF_DESTINATION}" extracted_file
)
message(STATUS "RF1485 single-file archive fixture passed: ${extracted_file}")

