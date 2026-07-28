cmake_minimum_required(VERSION 4.4.0)

# Rejection cases for the TASK-0001 resolution R1 and R3 admission rules.
# Both rules take their input as an argument rather than reading the running
# CMake version or the live registry, so each rejection is exercised against
# fabricated input without a second CMake installation or a modified host.

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_CASE)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1570 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")

if(RF_CASE STREQUAL "cmake_release_candidate")
    rf_admit_bootstrap_cmake_version("4.4.0-rc1" "4.4.0" admitted)

elseif(RF_CASE STREQUAL "cmake_vendor_build")
    rf_admit_bootstrap_cmake_version("4.4.0-msvc1" "4.4.0" admitted)

elseif(RF_CASE STREQUAL "cmake_other_stable_release")
    # A newer upstream stable release is still not the locked identity. The
    # rule is exact equality, not a floor.
    rf_admit_bootstrap_cmake_version("4.5.0" "4.4.0" admitted)

elseif(RF_CASE STREQUAL "cmake_locked_identity_admitted")
    # The positive case belongs beside the negatives so a rule that rejects
    # everything cannot pass this suite.
    rf_admit_bootstrap_cmake_version("4.4.0" "4.4.0" admitted)
    if(NOT admitted STREQUAL "4.4.0")
        message(FATAL_ERROR "RF1571 the locked CMake identity returned an unexpected base version")
    endif()
    message(FATAL_ERROR "RF1573 admission rule case '${RF_CASE}' behaved as specified")

elseif(RF_CASE STREQUAL "os_revision_below_floor")
    rf_admit_host_os_revision("8654" "8655" "fixture host")

elseif(RF_CASE STREQUAL "os_revision_not_integer")
    rf_admit_host_os_revision("8655.1" "8655" "fixture host")

elseif(RF_CASE STREQUAL "os_revision_at_and_above_floor_admitted")
    rf_admit_host_os_revision("8655" "8655" "fixture host")
    rf_admit_host_os_revision("8875" "8655" "fixture host")
    message(FATAL_ERROR "RF1573 admission rule case '${RF_CASE}' behaved as specified")

else()
    message(FATAL_ERROR "RF1572 unknown admission rule case: ${RF_CASE}")
endif()

message(FATAL_ERROR "RF1574 admission rule case '${RF_CASE}' unexpectedly succeeded")
