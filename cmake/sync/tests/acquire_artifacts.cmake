cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_HOST RF_TRANSPORT RF_ARTIFACT_IDS)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1486 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
foreach(artifact_id IN LISTS RF_ARTIFACT_IDS)
    rf_sync_acquire_artifact(
        "${RF_REPOSITORY_ROOT}" "${RF_HOST}" "${RF_TRANSPORT}" "${artifact_id}" acquired
    )
    message(STATUS "RF1487 ${artifact_id}=${acquired_path}")
endforeach()

