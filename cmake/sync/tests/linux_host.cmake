cmake_minimum_required(VERSION 4.4.0)

if(NOT DEFINED RF_REPOSITORY_ROOT)
    message(FATAL_ERROR "RF1558 RF_REPOSITORY_ROOT is required")
endif()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/linux_host.cmake")

rf_probe_linux_host_tuple("${RF_REPOSITORY_ROOT}")
message(STATUS "RF1559 locked Linux host tuple probed")
