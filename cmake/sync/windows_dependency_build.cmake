cmake_minimum_required(VERSION 4.4.0)

# Builds the locked Windows dependency closure completely offline through the
# prepared vcpkg, filesystem registry, seeded downloads, and seeded tool cache,
# then publishes the installed tree atomically. No step may acquire bytes from
# the network; vcpkg runs with --no-downloads and a cleared binary source.

if(NOT DEFINED RF_OPERATION OR NOT RF_OPERATION STREQUAL "dependencies")
    message(FATAL_ERROR "RF1515 Windows dependency build accepts only RF_OPERATION=dependencies")
endif()
if(NOT DEFINED RF_REPOSITORY_ROOT)
    cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH cmake_root)
    cmake_path(GET cmake_root PARENT_PATH RF_REPOSITORY_ROOT)
endif()
set(RF_HOST "windows-x86_64")

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/verifier.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/windows_host.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/windows_dependencies.cmake")

set(prepared_root "${RF_REPOSITORY_ROOT}/out/prepared/${RF_HOST}")
set(prepared_tools "${prepared_root}/tools")
set(sync_root "${RF_REPOSITORY_ROOT}/out/sync/${RF_HOST}")
set(downloads_root "${RF_REPOSITORY_ROOT}/out/cache/vcpkg-downloads")

rf_probe_windows_host_tuple("${RF_REPOSITORY_ROOT}")
rf_prepare_windows_dependency_authority("${RF_REPOSITORY_ROOT}")
rf_seed_windows_vcpkg_downloads("${RF_REPOSITORY_ROOT}")
rf_seed_windows_vcpkg_tool_trees("${RF_REPOSITORY_ROOT}")

file(REMOVE_RECURSE
    "${sync_root}/vcpkg-buildtrees"
    "${sync_root}/vcpkg-packages"
    "${prepared_root}/installed.incoming")
file(GLOB download_debris
    "${downloads_root}/*.part"
    "${downloads_root}/7z2602-x64.7z"
    "${downloads_root}/tools/*.partial.*")
foreach(debris IN LISTS download_debris)
    file(REMOVE_RECURSE "${debris}")
endforeach()
file(MAKE_DIRECTORY "${sync_root}/vcpkg-buildtrees" "${sync_root}/vcpkg-packages")

include("${prepared_root}/msvc-environment.cmake")
set(path_entries
    "${RF_MSVC_VCToolsInstallDir}bin\\Hostx64\\x64"
    "${RF_MSVC_WindowsSdkDir}bin\\${RF_MSVC_UCRTVersion}\\x64")
foreach(tool_directory IN ITEMS
        "tools/llvm/bin" "tools/cmake/bin" "tools/ninja" "tools/perl/perl/bin"
        "tools/nasm" "tools/powershell")
    file(TO_NATIVE_PATH "${prepared_root}/${tool_directory}" native_tool_directory)
    list(APPEND path_entries "${native_tool_directory}")
endforeach()
list(APPEND path_entries "C:\\Windows\\System32" "C:\\Windows")
list(JOIN path_entries ";" build_path)

set(vcpkg_executable "${prepared_root}/vcpkg/vcpkg.exe")
set(install_log "${sync_root}/vcpkg-install.log")
set(install_error_log "${sync_root}/vcpkg-install-error.log")
file(REMOVE "${install_log}" "${install_error_log}")
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
        "PATH=${build_path}"
        "INCLUDE=${RF_MSVC_INCLUDE}"
        "LIB=${RF_MSVC_LIB}"
        "LIBPATH=${RF_MSVC_LIBPATH}"
        "VSINSTALLDIR=${RF_MSVC_VSINSTALLDIR}"
        "VCINSTALLDIR=${RF_MSVC_VCINSTALLDIR}"
        "VCToolsInstallDir=${RF_MSVC_VCToolsInstallDir}"
        "VCToolsVersion=${RF_MSVC_VCToolsVersion}"
        "WindowsSdkDir=${RF_MSVC_WindowsSdkDir}"
        "WindowsSDKVersion=${RF_MSVC_WindowsSDKVersion}"
        "WindowsSDKLibVersion=${RF_MSVC_WindowsSDKLibVersion}"
        "UCRTVersion=${RF_MSVC_UCRTVersion}"
        "VSCMD_ARG_HOST_ARCH=${RF_MSVC_VSCMD_ARG_HOST_ARCH}"
        "VSCMD_ARG_TGT_ARCH=${RF_MSVC_VSCMD_ARG_TGT_ARCH}"
        "RAWFRAME_PREPARED_PERL_BIN=${prepared_root}/tools/perl/perl/bin"
        "RAWFRAME_PREPARED_NASM_DIR=${prepared_root}/tools/nasm"
        "RAWFRAME_PREPARED_MSVC_BIN=${RF_MSVC_VCToolsInstallDir}bin\\Hostx64\\x64"
        "RAWFRAME_PREPARED_SDK_BIN=${RF_MSVC_WindowsSdkDir}bin\\${RF_MSVC_UCRTVersion}\\x64"
        "VCPKG_KEEP_ENV_VARS=RAWFRAME_PREPARED_PERL_BIN;RAWFRAME_PREPARED_NASM_DIR;RAWFRAME_PREPARED_MSVC_BIN;RAWFRAME_PREPARED_SDK_BIN;INCLUDE;LIB;LIBPATH"
        "VCPKG_DISABLE_METRICS=1"
        "${vcpkg_executable}" install
        --triplet x64-windows-rawframe
        --host-triplet x64-windows-rawframe
        "--vcpkg-root=${prepared_root}/vcpkg"
        "--x-manifest-root=${prepared_root}/dependency-manifest"
        "--x-install-root=${prepared_root}/installed.incoming"
        "--x-buildtrees-root=${sync_root}/vcpkg-buildtrees"
        "--x-packages-root=${sync_root}/vcpkg-packages"
        "--downloads-root=${downloads_root}"
        --no-downloads
        --binarysource=clear
        --clean-buildtrees-after-build
    WORKING_DIRECTORY "${prepared_root}/dependency-manifest"
    RESULT_VARIABLE install_result
    OUTPUT_FILE "${install_log}"
    ERROR_FILE "${install_error_log}"
    TIMEOUT 7200
)
if(NOT install_result EQUAL 0)
    set(install_diagnostic "")
    if(EXISTS "${install_error_log}")
        file(SIZE "${install_error_log}" error_bytes)
        if(error_bytes GREATER 4096)
            math(EXPR error_offset "${error_bytes} - 4096")
            file(READ "${install_error_log}" install_diagnostic OFFSET ${error_offset})
        elseif(error_bytes GREATER 0)
            file(READ "${install_error_log}" install_diagnostic)
        endif()
    endif()
    rf_bootstrap_fail("RF1516" "offline vcpkg dependency build failed: ${install_diagnostic}")
endif()

set(installed_triplet "${prepared_root}/installed.incoming/x64-windows-rawframe")
foreach(required IN ITEMS
        "include/simdjson.h"
        "include/gtest/gtest.h"
        "include/gmock/gmock.h"
        "include/openssl/ssl.h"
        "include/openssl/evp.h"
        "include/openssl/opensslv.h"
        "lib/simdjson.lib"
        "lib/gtest.lib"
        "lib/gmock.lib"
        "lib/manual-link/gtest_main.lib"
        "lib/manual-link/gmock_main.lib"
        "lib/libcrypto.lib"
        "lib/libssl.lib")
    if(NOT EXISTS "${installed_triplet}/${required}")
        rf_bootstrap_fail("RF1517" "installed dependency closure is missing ${required}")
    endif()
    file(SIZE "${installed_triplet}/${required}" required_bytes)
    if(required_bytes EQUAL 0)
        rf_bootstrap_fail("RF1517" "installed dependency artifact is empty: ${required}")
    endif()
endforeach()
if(IS_DIRECTORY "${installed_triplet}/debug")
    rf_bootstrap_fail("RF1517" "release-only closure unexpectedly contains a debug tree")
endif()
if(NOT EXISTS "${prepared_root}/installed.incoming/vcpkg/status")
    rf_bootstrap_fail("RF1517" "vcpkg installation database is missing")
endif()

file(WRITE "${prepared_root}/installed.incoming/.rf-prepared.json"
    "{\n"
    "  \"host\": \"${RF_HOST}\",\n"
    "  \"kind\": \"vcpkg-installed-closure\",\n"
    "  \"triplet\": \"x64-windows-rawframe\",\n"
    "  \"packages\": [\"gtest\", \"openssl\", \"simdjson\"],\n"
    "  \"registryBaseline\": \"rawframe_task_0001\",\n"
    "  \"offline\": true\n"
    "}\n")
set(installed_destination "${prepared_root}/installed")
set(installed_previous "${installed_destination}.previous")
if(EXISTS "${installed_previous}")
    rf_bootstrap_fail("RF1518" "stale installed-closure rollback state exists")
endif()
if(EXISTS "${installed_destination}")
    file(RENAME "${installed_destination}" "${installed_previous}" RESULT stage_result)
    if(NOT stage_result STREQUAL "0")
        rf_bootstrap_fail("RF1519" "cannot stage existing installed closure for replacement")
    endif()
endif()
file(RENAME "${prepared_root}/installed.incoming" "${installed_destination}" RESULT publish_result)
if(NOT publish_result STREQUAL "0")
    if(EXISTS "${installed_previous}")
        file(RENAME "${installed_previous}" "${installed_destination}" RESULT rollback_result)
    endif()
    rf_bootstrap_fail("RF1519" "cannot atomically publish the installed dependency closure")
endif()
file(REMOVE_RECURSE "${installed_previous}")

file(MAKE_DIRECTORY "${RF_REPOSITORY_ROOT}/out/reports/task-0001/${RF_HOST}")
file(WRITE "${RF_REPOSITORY_ROOT}/out/reports/task-0001/${RF_HOST}/dependencies.json.tmp"
    "{\n"
    "  \"host\": \"${RF_HOST}\",\n"
    "  \"triplet\": \"x64-windows-rawframe\",\n"
    "  \"packages\": [\"gtest\", \"openssl\", \"simdjson\"],\n"
    "  \"registryBaseline\": \"rawframe_task_0001\",\n"
    "  \"network\": \"denied\",\n"
    "  \"binaryCache\": \"cleared\",\n"
    "  \"state\": \"installed_published\"\n"
    "}\n")
file(RENAME
    "${RF_REPOSITORY_ROOT}/out/reports/task-0001/${RF_HOST}/dependencies.json.tmp"
    "${RF_REPOSITORY_ROOT}/out/reports/task-0001/${RF_HOST}/dependencies.json")
message(STATUS "RF1520 Windows dependency closure built offline and published")
