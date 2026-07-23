cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_HOST RF_TRANSPORT RF_SIGNTOOL)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1498 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authenticode.cmake")
rf_sync_acquire_artifact(
    "${RF_REPOSITORY_ROOT}" "${RF_HOST}" "${RF_TRANSPORT}" "tool.vcpkg.windows_x86_64" vcpkg_windows
)
rf_verify_windows_authenticode(
    "${RF_SIGNTOOL}" 543144 "e7b517a6a2828af2d1fba3da60ae1e322a95141bfae192622725329630caa2b3"
    "${vcpkg_windows_path}" "1D77A9B9E8FE2075D9AD15123257FB90DB0DA4A1" "vcpkg 2026.07.13 Windows tool"
)
message(STATUS "RF1499 Authenticode fixture passed without CAS publication")

