include_guard(GLOBAL)

# Probes the exact TASK-0001 locked Windows host tuple `host.windows_11_25h2_x86_64`.
# Every locked value is mechanically probed; PATH presence never admits a component.

# The locked SignTool identity is owned by the bootstrap signature file, because
# Stage 0 admits its transport before this probe runs. Include it rather than
# restating those values here.
include("${CMAKE_CURRENT_LIST_DIR}/../bootstrap/windows_signature.cmake")

# TASK-0001 resolution R1 admits the operating system at generation plus a
# revision floor instead of an exact build. Exact operating-system build
# identity belongs to the ADR-0020/SPEC-0015 benchmark cell fingerprint, not
# to a Tier-0 correctness tool, and an exact-build gate would fail on every
# cumulative update, which sets this Task against the ADR-0079 rule that
# security updates are applied promptly. The measured revision is recorded as
# evidence in the host tuple report. Every other value below stays exact.
# ADR-0083 admits a second host class whose operating-system identity is its
# image digest. That replaces the four self-reported values below and nothing
# else: inside a container host the Visual Studio, MSVC, compiler, linker, SDK,
# and SignTool identities are probed exactly as they are on a workstation, and a
# container that drifts fails the same checks for the same reasons.
#
# Only the operating-system values are replaced because only they describe the
# base layer rather than the environment. A digest over the whole image is
# strictly stronger evidence than a build number the machine reports about
# itself, which is why this is a strengthening and not a concession.
set(RF_WINDOWS_CONTAINER_HOST_ID "host.container_windows_servercore_ltsc2025_x86_64")
set(RF_WINDOWS_CONTAINER_HOST_MARKER "C:/rf/host-identity.json")
set(RF_WINDOWS_HOST_OS_BUILD "26200")
set(RF_WINDOWS_HOST_OS_UBR_MINIMUM "8655")
set(RF_WINDOWS_HOST_OS_DISPLAY_VERSION "25H2")
set(RF_WINDOWS_HOST_OS_EDITION "Professional")
# The owner-approved 2026-07-16 amendment admits exactly two Visual Studio
# instances for this tuple: the Community 18.7.3 instance recorded on the
# reference development host, and the Build Tools 18.7.3 instance the
# clean-host verification VM installs, because Microsoft publishes fixed-
# version bootstrappers for Build Tools but not for Community. Both carry
# the identical 18.7.11925.98 product build, MSVC toolset, cl, nmake, and
# vcvars64 projection; a probed host must carry exactly one of them.
set(RF_WINDOWS_HOST_VS_ADMITTED_ROOTS
    "C:/Program Files/Microsoft Visual Studio/18/Community"
    "C:/Program Files/Microsoft Visual Studio/18/BuildTools")
set(RF_WINDOWS_HOST_VS_VERSION "18.7.11925.98")
set(RF_WINDOWS_HOST_VS_INSTANCE_ROOT "C:/ProgramData/Microsoft/VisualStudio/Packages/_Instances")
set(RF_WINDOWS_HOST_MSVC_TOOLSET "14.51.36231")
set(RF_WINDOWS_HOST_CL_VERSION "19.51.36248")
set(RF_WINDOWS_HOST_NMAKE_VERSION "14.51.36248.0")
set(RF_WINDOWS_HOST_SDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
set(RF_WINDOWS_HOST_SDK_GENERATION "10.0.26100.0")
set(RF_WINDOWS_HOST_SDK_PRODUCT_VERSION "10.0.26100")
set(RF_WINDOWS_HOST_SDK_PACKAGE_VERSION "10.1.26100.8249")
set(RF_WINDOWS_HOST_SDK_PACKAGE_GUID "{204d0387-6d9a-48cf-bb7d-93d49ec0141c}")
# The locked SignTool identity is owned by cmake/bootstrap/windows_signature.cmake
# because Stage 0 needs it before this probe runs. Do not restate it here.

# Resolves which ADR-0083 host class this probe is running under.
#
# The marker states what the environment is, never what it may be trusted with.
# A hand-built image can carry the same file and still produces
# `diagnostic_untrusted` evidence, because trust comes from an ADR-0082
# attestation over the protected workflow and from nothing else. The digest that
# makes a container an identity is enforced by whoever starts it, which is the
# only place it can be known, so this function must not pretend to check it.
function(rf_resolve_windows_host_class output_class output_host_id)
    if(NOT EXISTS "${RF_WINDOWS_CONTAINER_HOST_MARKER}")
        set(${output_class} "workstation" PARENT_SCOPE)
        set(${output_host_id} "host.windows_11_25h2_x86_64" PARENT_SCOPE)
        return()
    endif()
    file(READ "${RF_WINDOWS_CONTAINER_HOST_MARKER}" marker_text LIMIT 4096)
    string(JSON marker_class ERROR_VARIABLE class_error GET "${marker_text}" hostClass)
    string(JSON marker_host ERROR_VARIABLE host_error GET "${marker_text}" hostId)
    string(JSON marker_probe ERROR_VARIABLE probe_error GET "${marker_text}" probeHostId)
    if(class_error OR host_error OR probe_error)
        rf_bootstrap_fail("RF1510" "container host identity marker is unreadable")
    endif()
    if(NOT marker_class STREQUAL "container" OR
       NOT marker_host STREQUAL RF_WINDOWS_CONTAINER_HOST_ID OR
       NOT marker_probe STREQUAL "windows-x86_64")
        rf_bootstrap_fail("RF1511" "container host identity marker names a different host")
    endif()
    set(${output_class} "container" PARENT_SCOPE)
    set(${output_host_id} "${RF_WINDOWS_CONTAINER_HOST_ID}" PARENT_SCOPE)
endfunction()

function(rf_probe_windows_os_identity)
    cmake_host_system_information(RESULT build_number QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" VALUE "CurrentBuildNumber")
    if(NOT build_number STREQUAL RF_WINDOWS_HOST_OS_BUILD)
        rf_bootstrap_fail("RF1500" "host OS build number differs from the locked tuple")
    endif()
    cmake_host_system_information(RESULT ubr QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" VALUE "UBR")
    rf_admit_host_os_revision("${ubr}" "${RF_WINDOWS_HOST_OS_UBR_MINIMUM}" "host OS")
    set(RF_WINDOWS_HOST_OS_UBR_MEASURED "${ubr}" PARENT_SCOPE)
    cmake_host_system_information(RESULT display_version QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" VALUE "DisplayVersion")
    cmake_host_system_information(RESULT edition QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion" VALUE "EditionID")
    if(NOT display_version STREQUAL RF_WINDOWS_HOST_OS_DISPLAY_VERSION OR
       NOT edition STREQUAL RF_WINDOWS_HOST_OS_EDITION)
        rf_bootstrap_fail("RF1502" "host OS display version or edition differs from the locked tuple")
    endif()
endfunction()

function(rf_probe_windows_visual_studio)
    file(GLOB state_files "${RF_WINDOWS_HOST_VS_INSTANCE_ROOT}/*/state.json")
    set(matched_roots "")
    set(matched_versions "")
    foreach(state_file IN LISTS state_files)
        file(SIZE "${state_file}" state_bytes)
        if(state_bytes GREATER 1048576)
            continue()
        endif()
        file(READ "${state_file}" state_content)
        file(READ "${state_file}" state_prefix_hex LIMIT 3 HEX)
        if(state_prefix_hex STREQUAL "efbbbf")
            string(SUBSTRING "${state_content}" 3 -1 state_content)
        endif()
        string(JSON instance_path ERROR_VARIABLE path_error GET "${state_content}" installationPath)
        if(path_error)
            continue()
        endif()
        foreach(admitted_root IN LISTS RF_WINDOWS_HOST_VS_ADMITTED_ROOTS)
            file(TO_NATIVE_PATH "${admitted_root}" admitted_native_root)
            if(instance_path STREQUAL admitted_native_root)
                string(JSON instance_version ERROR_VARIABLE version_error
                    GET "${state_content}" installationVersion)
                if(version_error)
                    rf_bootstrap_fail("RF1503" "admitted Visual Studio instance record is unreadable")
                endif()
                list(APPEND matched_roots "${admitted_root}")
                list(APPEND matched_versions "${instance_version}")
            endif()
        endforeach()
    endforeach()
    list(LENGTH matched_roots matched_count)
    if(NOT matched_count EQUAL 1)
        rf_bootstrap_fail("RF1503" "the host must carry exactly one admitted Visual Studio instance")
    endif()
    list(GET matched_versions 0 vs_version)
    if(NOT vs_version STREQUAL RF_WINDOWS_HOST_VS_VERSION)
        rf_bootstrap_fail("RF1504" "Visual Studio installation version differs from the locked tuple")
    endif()
    list(GET matched_roots 0 resolved_root)
    set(RF_WINDOWS_HOST_VS_ROOT "${resolved_root}" PARENT_SCOPE)

    set(default_toolset_file
        "${resolved_root}/VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt")
    if(NOT EXISTS "${default_toolset_file}")
        rf_bootstrap_fail("RF1505" "MSVC default toolset authority file is missing")
    endif()
    file(READ "${default_toolset_file}" default_toolset LIMIT 256)
    string(STRIP "${default_toolset}" default_toolset)
    set(toolset_root "${resolved_root}/VC/Tools/MSVC/${RF_WINDOWS_HOST_MSVC_TOOLSET}")
    if(NOT default_toolset STREQUAL RF_WINDOWS_HOST_MSVC_TOOLSET OR NOT IS_DIRECTORY "${toolset_root}")
        rf_bootstrap_fail("RF1505" "MSVC default toolset differs from the locked tuple")
    endif()

    set(cl_executable "${toolset_root}/bin/Hostx64/x64/cl.exe")
    execute_process(
        COMMAND "${cl_executable}"
        RESULT_VARIABLE cl_result OUTPUT_VARIABLE cl_output ERROR_VARIABLE cl_error TIMEOUT 30
    )
    string(REPLACE "." "\\." cl_version_pattern "${RF_WINDOWS_HOST_CL_VERSION}")
    if(NOT cl_result EQUAL 0 OR NOT "${cl_output}${cl_error}" MATCHES
       "C/C\\+\\+ Optimizing Compiler Version ${cl_version_pattern}(\\.0)? for x64")
        rf_bootstrap_fail("RF1506" "cl.exe identity differs from the locked tuple")
    endif()

    set(nmake_executable "${toolset_root}/bin/Hostx64/x64/nmake.exe")
    execute_process(
        COMMAND "${nmake_executable}" /?
        RESULT_VARIABLE nmake_result OUTPUT_VARIABLE nmake_output ERROR_VARIABLE nmake_error TIMEOUT 30
    )
    string(REPLACE "." "\\." nmake_version_pattern "${RF_WINDOWS_HOST_NMAKE_VERSION}")
    if(NOT nmake_result EQUAL 0 OR NOT "${nmake_output}${nmake_error}" MATCHES
       " ${nmake_version_pattern}")
        rf_bootstrap_fail("RF1507" "nmake.exe identity differs from the locked tuple")
    endif()
endfunction()

function(rf_probe_windows_sdk)
    foreach(required IN ITEMS
            "Include/${RF_WINDOWS_HOST_SDK_GENERATION}/um/windows.h"
            "Include/${RF_WINDOWS_HOST_SDK_GENERATION}/ucrt/corecrt.h"
            "Include/${RF_WINDOWS_HOST_SDK_GENERATION}/shared/winerror.h"
            "Lib/${RF_WINDOWS_HOST_SDK_GENERATION}/um/x64/kernel32.lib"
            "Lib/${RF_WINDOWS_HOST_SDK_GENERATION}/ucrt/x64/libucrt.lib")
        if(NOT EXISTS "${RF_WINDOWS_HOST_SDK_ROOT}/${required}")
            rf_bootstrap_fail("RF1508" "Windows SDK ${RF_WINDOWS_HOST_SDK_GENERATION} tree is incomplete")
        endif()
    endforeach()
    cmake_host_system_information(RESULT sdk_product QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/Microsoft/Microsoft SDKs/Windows/v10.0" VALUE "ProductVersion" VIEW 32)
    if(NOT sdk_product STREQUAL RF_WINDOWS_HOST_SDK_PRODUCT_VERSION)
        rf_bootstrap_fail("RF1509" "Windows SDK product version differs from the locked tuple")
    endif()
    cmake_host_system_information(RESULT sdk_package QUERY WINDOWS_REGISTRY
        "HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/${RF_WINDOWS_HOST_SDK_PACKAGE_GUID}"
        VALUE "DisplayVersion" VIEW 32)
    if(NOT sdk_package STREQUAL RF_WINDOWS_HOST_SDK_PACKAGE_VERSION)
        rf_bootstrap_fail("RF1509" "Windows SDK package version differs from the locked tuple")
    endif()
    rf_verify_file_identity("${RF_WINDOWS_HOST_SIGNTOOL}" "${RF_WINDOWS_HOST_SIGNTOOL_BYTES}"
        "${RF_WINDOWS_HOST_SIGNTOOL_SHA256}" "locked SignTool")
endfunction()

function(rf_capture_windows_msvc_environment repository_root)
    set(probe_root "${repository_root}/out/sync/windows-x86_64/host-probe")
    file(MAKE_DIRECTORY "${probe_root}")
    file(TO_NATIVE_PATH "${RF_WINDOWS_HOST_VS_ROOT}/VC/Auxiliary/Build/vcvars64.bat" vcvars_native)
    set(capture_script "${probe_root}/capture-vcvars64.bat")
    set(capture_log "${probe_root}/vcvars64-log.txt")
    file(REMOVE "${capture_log}")
    file(TO_NATIVE_PATH "${capture_log}" capture_log_native)
    file(WRITE "${capture_script}"
        "@echo off\r\n"
        "set \"PATH=C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\"\r\n"
        "set \"VSCMD_SKIP_SENDTELEMETRY=1\"\r\n"
        "call \"${vcvars_native}\" > \"${capture_log_native}\" 2>&1\r\n"
        "if errorlevel 1 exit /b 7\r\n"
        "set\r\n")
    file(TO_NATIVE_PATH "${capture_script}" capture_native)
    execute_process(
        COMMAND "${capture_native}"
        RESULT_VARIABLE capture_result OUTPUT_VARIABLE capture_output ERROR_VARIABLE capture_error
        TIMEOUT 120
    )
    if(NOT capture_result EQUAL 0)
        set(capture_diagnostic "")
        if(EXISTS "${capture_log}")
            file(READ "${capture_log}" capture_diagnostic LIMIT 2048)
        endif()
        rf_bootstrap_fail("RF1510" "vcvars64 environment capture failed: ${capture_diagnostic}")
    endif()

    string(REPLACE "\r" "" capture_output "${capture_output}")
    set(allowed_variables
        INCLUDE LIB LIBPATH VCINSTALLDIR VSINSTALLDIR VCToolsInstallDir VCToolsVersion
        WindowsSdkDir WindowsSDKVersion WindowsSDKLibVersion UCRTVersion
        VSCMD_ARG_HOST_ARCH VSCMD_ARG_TGT_ARCH VSCMD_VER)
    foreach(variable IN LISTS allowed_variables)
        set(captured_${variable} "")
        if(capture_output MATCHES "(^|\n)${variable}=([^\n]*)")
            set(captured_${variable} "${CMAKE_MATCH_2}")
        endif()
    endforeach()

    file(TO_NATIVE_PATH "${RF_WINDOWS_HOST_VS_ROOT}" vs_native_root)
    file(TO_NATIVE_PATH "${RF_WINDOWS_HOST_SDK_ROOT}" sdk_native_root)
    set(expected_VCToolsVersion "${RF_WINDOWS_HOST_MSVC_TOOLSET}")
    set(expected_WindowsSDKVersion "${RF_WINDOWS_HOST_SDK_GENERATION}\\")
    set(expected_WindowsSDKLibVersion "${RF_WINDOWS_HOST_SDK_GENERATION}\\")
    set(expected_UCRTVersion "${RF_WINDOWS_HOST_SDK_GENERATION}")
    set(expected_VSCMD_ARG_HOST_ARCH "x64")
    set(expected_VSCMD_ARG_TGT_ARCH "x64")
    set(expected_VSCMD_VER "18.0")
    set(expected_VSINSTALLDIR "${vs_native_root}\\")
    set(expected_VCINSTALLDIR "${vs_native_root}\\VC\\")
    set(expected_VCToolsInstallDir
        "${vs_native_root}\\VC\\Tools\\MSVC\\${RF_WINDOWS_HOST_MSVC_TOOLSET}\\")
    set(expected_WindowsSdkDir "${sdk_native_root}\\")
    foreach(variable IN ITEMS
            VCToolsVersion WindowsSDKVersion WindowsSDKLibVersion UCRTVersion
            VSCMD_ARG_HOST_ARCH VSCMD_ARG_TGT_ARCH VSCMD_VER
            VSINSTALLDIR VCINSTALLDIR VCToolsInstallDir WindowsSdkDir)
        if(NOT captured_${variable} STREQUAL expected_${variable})
            rf_bootstrap_fail("RF1511"
                "vcvars64 value for ${variable} differs from the locked tuple")
        endif()
    endforeach()
    foreach(variable IN ITEMS INCLUDE LIB LIBPATH)
        if(captured_${variable} STREQUAL "")
            rf_bootstrap_fail("RF1511" "vcvars64 did not produce ${variable}")
        endif()
    endforeach()

    set(projection "")
    foreach(variable IN LISTS allowed_variables)
        string(REPLACE "\\" "\\\\" escaped_value "${captured_${variable}}")
        string(REPLACE "\"" "\\\"" escaped_value "${escaped_value}")
        string(APPEND projection "set(RF_MSVC_${variable} \"${escaped_value}\")\n")
    endforeach()
    set(projection_path "${repository_root}/out/prepared/windows-x86_64/msvc-environment.cmake")
    file(WRITE "${projection_path}.tmp" "${projection}")
    file(RENAME "${projection_path}.tmp" "${projection_path}")
endfunction()

function(rf_probe_windows_host_tuple repository_root)
    rf_resolve_windows_host_class(host_class host_id)
    if(host_class STREQUAL "container")
        # The operating-system values below describe the base layer, and the
        # image digest that names the whole environment has already replaced
        # them. Recording them as measured would be a false claim, so they are
        # recorded as what they are.
        set(RF_WINDOWS_HOST_OS_UBR_MEASURED "container")
        set(os_build "${RF_WINDOWS_CONTAINER_HOST_ID}")
        set(os_display_version "container")
        set(os_edition "container")
    else()
        rf_probe_windows_os_identity()
        set(os_build "${RF_WINDOWS_HOST_OS_BUILD}.${RF_WINDOWS_HOST_OS_UBR_MEASURED}")
        set(os_display_version "${RF_WINDOWS_HOST_OS_DISPLAY_VERSION}")
        set(os_edition "${RF_WINDOWS_HOST_OS_EDITION}")
    endif()
    rf_probe_windows_visual_studio()
    rf_probe_windows_sdk()
    rf_capture_windows_msvc_environment("${repository_root}")

    cmake_path(GET RF_WINDOWS_HOST_VS_ROOT FILENAME vs_probed_instance)
    set(report_root "${repository_root}/out/reports/task-0001/windows-x86_64")
    file(MAKE_DIRECTORY "${report_root}")
    file(WRITE "${report_root}/host-tuple.json.tmp"
        "{\n"
        "  \"host\": \"${host_id}\",\n"
        "  \"hostClass\": \"${host_class}\",\n"
        "  \"osBuild\": \"${os_build}\",\n"
        "  \"osUpdateBuildRevisionMinimum\": \"${RF_WINDOWS_HOST_OS_UBR_MINIMUM}\",\n"
        "  \"osDisplayVersion\": \"${os_display_version}\",\n"
        "  \"osEdition\": \"${os_edition}\",\n"
        "  \"visualStudioVersion\": \"${RF_WINDOWS_HOST_VS_VERSION}\",\n"
        "  \"visualStudioInstance\": \"${vs_probed_instance}\",\n"
        "  \"msvcToolset\": \"${RF_WINDOWS_HOST_MSVC_TOOLSET}\",\n"
        "  \"clVersion\": \"${RF_WINDOWS_HOST_CL_VERSION}.0\",\n"
        "  \"windowsSdkPackage\": \"${RF_WINDOWS_HOST_SDK_PACKAGE_VERSION}\",\n"
        "  \"windowsSdkGeneration\": \"${RF_WINDOWS_HOST_SDK_GENERATION}\",\n"
        "  \"state\": \"probed\"\n"
        "}\n")
    file(RENAME "${report_root}/host-tuple.json.tmp" "${report_root}/host-tuple.json")
endfunction()
