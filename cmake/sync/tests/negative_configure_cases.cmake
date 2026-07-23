cmake_minimum_required(VERSION 4.4.0)

# Negative configure probes. Each case runs a real preset configure in a
# scratch binary directory with one forbidden provider substitution and must
# fail before any production compilation, emitting the exact RF diagnostic
# that CTest asserts through PASS_REGULAR_EXPRESSION. The child inherits the
# captured locked MSVC environment so compiler detection itself succeeds and
# the policy check is what fails.

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_CASE RF_SCRATCH)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1545 ${argument} is required")
    endif()
endforeach()

set(prepared_root "${RF_REPOSITORY_ROOT}/out/prepared/windows-x86_64")
set(msvc_environment "${prepared_root}/msvc-environment.cmake")
if(NOT EXISTS "${msvc_environment}")
    message(FATAL_ERROR "RF1546 captured MSVC environment is required for negative configure probes")
endif()
include("${msvc_environment}")

set(case_scratch "${RF_SCRATCH}/${RF_CASE}")
file(REMOVE_RECURSE "${case_scratch}")
file(MAKE_DIRECTORY "${case_scratch}")

set(case_arguments "")
if(RF_CASE STREQUAL "msvc_frontend")
    # cl.exe try-compile linking needs mt.exe, which the locked closure does
    # not provide, so compiler validation would fail before the policy check.
    # Compile-only validation lets configure reach the RF1104 rejection that
    # this probe asserts.
    set(msvc_cl "${RF_MSVC_VCToolsInstallDir}bin\\Hostx64\\x64\\cl.exe")
    list(APPEND case_arguments
        "-DCMAKE_C_COMPILER=${msvc_cl}" "-DCMAKE_CXX_COMPILER=${msvc_cl}"
        "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY")
elseif(RF_CASE STREQUAL "vs_bundled_clang")
    set(bundled_clang
        "C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/bin/clang-cl.exe")
    if(NOT EXISTS "${bundled_clang}")
        message(FATAL_ERROR "RF1547 the locked host tuple must provide VS-bundled Clang for this probe")
    endif()
    list(APPEND case_arguments
        "-DCMAKE_C_COMPILER=${bundled_clang}" "-DCMAKE_CXX_COMPILER=${bundled_clang}")
elseif(RF_CASE STREQUAL "wrong_sdk")
    file(READ "${msvc_environment}" environment_content)
    string(REPLACE "10.0.26100.0" "10.0.22621.0" environment_content "${environment_content}")
    file(WRITE "${case_scratch}/msvc-environment-wrong-sdk.cmake" "${environment_content}")
    list(APPEND case_arguments
        "-DRAWFRAME_MSVC_ENVIRONMENT_FILE=${case_scratch}/msvc-environment-wrong-sdk.cmake")
elseif(RF_CASE STREQUAL "wrong_vcpkg_baseline")
    file(MAKE_DIRECTORY "${case_scratch}/installed")
    file(WRITE "${case_scratch}/installed/.rf-prepared.json"
        "{\n"
        "  \"host\": \"windows-x86_64\",\n"
        "  \"kind\": \"vcpkg-installed-closure\",\n"
        "  \"triplet\": \"x64-windows-rawframe\",\n"
        "  \"packages\": [\"gtest\", \"openssl\", \"simdjson\"],\n"
        "  \"registryBaseline\": \"ambient_wrong_baseline\",\n"
        "  \"offline\": true\n"
        "}\n")
    list(APPEND case_arguments "-DVCPKG_INSTALLED_DIR=${case_scratch}/installed")
elseif(RF_CASE STREQUAL "ambient_provider")
    file(MAKE_DIRECTORY "${case_scratch}/installed")
    list(APPEND case_arguments "-DVCPKG_INSTALLED_DIR=${case_scratch}/installed")
else()
    message(FATAL_ERROR "RF1548 unknown negative configure case: ${RF_CASE}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
        "INCLUDE=${RF_MSVC_INCLUDE}"
        "LIB=${RF_MSVC_LIB}"
        "${CMAKE_COMMAND}" --preset task-0001-windows-x86_64-debug --fresh
        -B "${case_scratch}/build" ${case_arguments}
    WORKING_DIRECTORY "${RF_REPOSITORY_ROOT}"
    RESULT_VARIABLE configure_result
    TIMEOUT 240
)

if(configure_result EQUAL 0)
    message(FATAL_ERROR "RF1549 negative configure case '${RF_CASE}' unexpectedly succeeded")
endif()
message(STATUS "negative configure case '${RF_CASE}' failed before compilation as required")
