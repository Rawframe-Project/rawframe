cmake_minimum_required(VERSION 4.4.0)

if(NOT DEFINED RF_REPOSITORY_ROOT)
    message(FATAL_ERROR "RF1474 RF_REPOSITORY_ROOT is required")
endif()
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/licenses.cmake")
rf_sync_verify_license_closure("${RF_REPOSITORY_ROOT}")
message(STATUS "RF1475 offline license closure fixture passed")

