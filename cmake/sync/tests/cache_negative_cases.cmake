cmake_minimum_required(VERSION 4.4.0)

# Offline cache negatives. The acquisition path must fail deterministically,
# never fall back to network, when the local cache is empty or corrupt.
# RF_TRANSPORT is a deliberately nonexistent executable, so any transport use
# fails with RF1249 instead of acquiring bytes.

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_CASE)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1533 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")

set(fixture_host "negative-cache-fixture")
set(fixture_sync "${RF_REPOSITORY_ROOT}/out/sync/${fixture_host}")
file(REMOVE_RECURSE "${fixture_sync}")

if(RF_CASE STREQUAL "empty_cache")
    rf_sync_acquire_artifact(
        "${RF_REPOSITORY_ROOT}" "${fixture_host}" "denied-no-transport"
        "tool.ninja.windows_x86_64" probe)
elseif(RF_CASE STREQUAL "corrupt_cache")
    file(MAKE_DIRECTORY "${fixture_sync}/quarantine")
    string(REPEAT "x" 291570 corrupt_bytes)
    file(WRITE
        "${fixture_sync}/quarantine/artifact-07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65"
        "${corrupt_bytes}")
    rf_sync_acquire_artifact(
        "${RF_REPOSITORY_ROOT}" "${fixture_host}" "denied-no-transport"
        "tool.ninja.windows_x86_64" probe)
else()
    message(FATAL_ERROR "RF1534 unknown cache negative case: ${RF_CASE}")
endif()

message(FATAL_ERROR "RF1535 cache negative case '${RF_CASE}' unexpectedly succeeded")
