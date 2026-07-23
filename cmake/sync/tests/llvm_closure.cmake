cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_HOST RF_TRANSPORT)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1482 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/llvm.cmake")
rf_sync_verify_llvm_closure(
    "${RF_REPOSITORY_ROOT}" "${RF_HOST}" "${RF_TRANSPORT}" verified_ids verified_paths
)
list(LENGTH verified_ids verified_count)
if(NOT verified_count EQUAL 4)
    message(FATAL_ERROR "RF1483 LLVM fixture returned an incomplete verified closure")
endif()
message(STATUS "RF1481 LLVM composite closure passed without CAS publication")

