cmake_minimum_required(VERSION 4.4.0)

if(NOT DEFINED RF_REPOSITORY_ROOT)
    cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH tests_parent)
    cmake_path(GET tests_parent PARENT_PATH sync_parent)
    cmake_path(GET sync_parent PARENT_PATH cmake_parent)
    cmake_path(GET cmake_parent PARENT_PATH RF_REPOSITORY_ROOT)
endif()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/verifier.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/windows_dependencies.cmake")

rf_prepare_windows_dependency_authority("${RF_REPOSITORY_ROOT}")
rf_seed_windows_vcpkg_downloads("${RF_REPOSITORY_ROOT}")
rf_seed_windows_vcpkg_tool_trees("${RF_REPOSITORY_ROOT}")

message(STATUS "RF1486 Windows offline dependency authority fixture passed")
