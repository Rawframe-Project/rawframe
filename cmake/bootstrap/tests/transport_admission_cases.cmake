cmake_minimum_required(VERSION 4.4.0)

# Rejection cases for the TASK-0001 resolution R2 transport admission rule.
# R2 replaced frozen transport bytes with an exact path, a version floor, and a
# vendor signature, so each of those three conditions needs a case that proves
# it rejects. A case that cannot reject is not an admission rule.

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_CASE RF_SCRATCH)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1560 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")

set(case_root "${RF_SCRATCH}/${RF_CASE}")
file(REMOVE_RECURSE "${case_root}")
file(MAKE_DIRECTORY "${case_root}")

if(RF_CASE STREQUAL "absent_transport")
    # RF1255. A locked path that holds nothing is not a transport.
    rf_verify_transport_executable(
        "${case_root}/no-such-curl" "8.19.0" "distribution_package_chain" measured)

elseif(RF_CASE STREQUAL "unknown_signature_class")
    # RF1256. An unrecognized vendor signature class is rejected rather than
    # treated as no requirement.
    if(WIN32)
        set(present_transport "C:/Windows/System32/curl.exe")
    else()
        set(present_transport "/usr/bin/curl")
    endif()
    rf_verify_transport_executable(
        "${present_transport}" "8.0.0" "trust_me" measured)

elseif(RF_CASE STREQUAL "version_below_floor")
    # RF1248. The floor is a real gate, not documentation. The measured inbox
    # transport cannot satisfy an impossible future minimum.
    if(WIN32)
        set(present_transport "C:/Windows/System32/curl.exe")
    else()
        set(present_transport "/usr/bin/curl")
    endif()
    rf_verify_transport_executable(
        "${present_transport}" "999.0.0" "distribution_package_chain" measured)

elseif(RF_CASE STREQUAL "unsigned_binary")
    # RF1442. An unsigned file at a plausible path fails the vendor signature
    # requirement on Windows. The file is a copy of the real transport with one
    # byte appended, so it exists and is an executable image, but its embedded
    # signature no longer covers its bytes.
    if(NOT WIN32)
        message(FATAL_ERROR "RF1561 the unsigned_binary case is Windows-only")
    endif()
    set(tampered "${case_root}/curl.exe")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E copy "C:/Windows/System32/curl.exe" "${tampered}"
        RESULT_VARIABLE copy_result)
    if(NOT copy_result EQUAL 0)
        message(FATAL_ERROR "RF1562 cannot stage the tampered transport copy")
    endif()
    file(APPEND "${tampered}" "rawframe-tamper")
    rf_verify_transport_executable(
        "${tampered}" "8.19.0" "authenticode_microsoft_windows" measured)

else()
    message(FATAL_ERROR "RF1563 unknown transport admission case: ${RF_CASE}")
endif()

message(FATAL_ERROR "RF1564 transport admission case '${RF_CASE}' unexpectedly succeeded")
