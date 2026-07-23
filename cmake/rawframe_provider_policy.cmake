include_guard(GLOBAL)

# Validates at configure time that compilation consumes only the prepared,
# locked provider closure: the prepared vcpkg toolchain, the published offline
# installed tree, the exact triplet, and, on Windows, the exact captured
# MSVC toolset and Windows SDK. Any ambient or mismatched provider fails
# before compilation. On Windows the verified toolset/SDK directories are
# pinned onto the compiler-policy interface so compilation and linking cannot
# drift to another installation through environment or auto-detection.

function(rawframe_validate_provider_closure)
    if(RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
        set(expected_triplet "x64-windows-rawframe")
    elseif(RAWFRAME_HOST_ID STREQUAL "linux-x86_64")
        set(expected_triplet "x64-linux-rawframe")
    else()
        message(FATAL_ERROR "RF1107 unsupported RAWFRAME_HOST_ID: ${RAWFRAME_HOST_ID}")
    endif()

    set(prepared_root "${CMAKE_SOURCE_DIR}/out/prepared/${RAWFRAME_HOST_ID}")

    if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
        message(FATAL_ERROR "RF1110 configure must chain the prepared vcpkg toolchain")
    endif()
    set(expected_toolchain "${prepared_root}/vcpkg/scripts/buildsystems/vcpkg.cmake")
    if(NOT EXISTS "${expected_toolchain}")
        message(FATAL_ERROR "RF1110 the prepared vcpkg toolchain is absent: ${expected_toolchain}")
    endif()
    file(REAL_PATH "${CMAKE_TOOLCHAIN_FILE}" observed_toolchain)
    file(REAL_PATH "${expected_toolchain}" expected_toolchain_real)
    string(TOLOWER "${observed_toolchain}" observed_toolchain_folded)
    string(TOLOWER "${expected_toolchain_real}" expected_toolchain_folded)
    if(NOT observed_toolchain_folded STREQUAL expected_toolchain_folded)
        message(FATAL_ERROR "RF1110 configure uses an ambient toolchain: ${CMAKE_TOOLCHAIN_FILE}")
    endif()

    if(NOT DEFINED VCPKG_MANIFEST_INSTALL OR VCPKG_MANIFEST_INSTALL)
        message(FATAL_ERROR "RF1111 vcpkg manifest installation must stay disabled at configure")
    endif()

    if(NOT DEFINED VCPKG_TARGET_TRIPLET OR NOT VCPKG_TARGET_TRIPLET STREQUAL expected_triplet)
        message(FATAL_ERROR "RF1114 configure must use the exact locked triplet ${expected_triplet}")
    endif()

    if(NOT DEFINED VCPKG_INSTALLED_DIR)
        message(FATAL_ERROR "RF1112 configure must name the prepared installed dependency tree")
    endif()
    set(installed_marker "${VCPKG_INSTALLED_DIR}/.rf-prepared.json")
    if(NOT EXISTS "${installed_marker}")
        message(FATAL_ERROR "RF1112 the installed dependency tree has no prepared marker")
    endif()
    file(READ "${installed_marker}" marker_json LIMIT 4096)
    string(JSON marker_kind ERROR_VARIABLE marker_error GET "${marker_json}" kind)
    if(marker_error OR NOT marker_kind STREQUAL "vcpkg-installed-closure")
        message(FATAL_ERROR "RF1113 the installed tree marker is not an offline vcpkg closure")
    endif()
    string(JSON marker_baseline ERROR_VARIABLE marker_error GET "${marker_json}" registryBaseline)
    if(marker_error OR NOT marker_baseline STREQUAL "rawframe_task_0001")
        message(FATAL_ERROR "RF1113 the installed tree was built from the wrong registry baseline")
    endif()
    string(JSON marker_triplet ERROR_VARIABLE marker_error GET "${marker_json}" triplet)
    if(marker_error OR NOT marker_triplet STREQUAL expected_triplet)
        message(FATAL_ERROR "RF1113 the installed tree was built for the wrong triplet")
    endif()
    string(JSON marker_offline ERROR_VARIABLE marker_error GET "${marker_json}" offline)
    if(marker_error OR NOT marker_offline STREQUAL "ON")
        string(TOLOWER "${marker_offline}" marker_offline_folded)
        if(NOT marker_offline_folded STREQUAL "true")
            message(FATAL_ERROR "RF1113 the installed tree does not declare offline provenance")
        endif()
    endif()

    if(NOT RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
        return()
    endif()

    if(NOT DEFINED RAWFRAME_MSVC_ENVIRONMENT_FILE)
        set(RAWFRAME_MSVC_ENVIRONMENT_FILE "${prepared_root}/msvc-environment.cmake")
    endif()
    if(NOT EXISTS "${RAWFRAME_MSVC_ENVIRONMENT_FILE}")
        message(FATAL_ERROR "RF1115 the captured MSVC environment is absent; run the Windows sync lane first")
    endif()
    include("${RAWFRAME_MSVC_ENVIRONMENT_FILE}")

    if(NOT DEFINED RF_MSVC_VCToolsVersion OR NOT RF_MSVC_VCToolsVersion STREQUAL "14.51.36231")
        message(FATAL_ERROR "RF1116 captured MSVC toolset differs from the locked host tuple")
    endif()
    if(NOT DEFINED RF_MSVC_UCRTVersion OR NOT RF_MSVC_UCRTVersion STREQUAL "10.0.26100.0")
        message(FATAL_ERROR "RF1116 captured Windows SDK differs from the locked host tuple")
    endif()

    cmake_path(CONVERT "${RF_MSVC_VCToolsInstallDir}" TO_CMAKE_PATH_LIST vctools_dir NORMALIZE)
    cmake_path(CONVERT "${RF_MSVC_WindowsSdkDir}" TO_CMAKE_PATH_LIST windows_sdk_dir NORMALIZE)
    string(REGEX REPLACE "/$" "" vctools_dir "${vctools_dir}")
    string(REGEX REPLACE "/$" "" windows_sdk_dir "${windows_sdk_dir}")
    foreach(required_directory IN ITEMS
            "${vctools_dir}/include"
            "${vctools_dir}/lib/x64"
            "${windows_sdk_dir}/Lib/${RF_MSVC_UCRTVersion}/ucrt/x64"
            "${windows_sdk_dir}/Lib/${RF_MSVC_UCRTVersion}/um/x64")
        if(NOT IS_DIRECTORY "${required_directory}")
            message(FATAL_ERROR "RF1117 locked toolset/SDK directory is absent: ${required_directory}")
        endif()
    endforeach()

    target_compile_options(rawframe_compiler_policy INTERFACE
        "SHELL:/vctoolsdir \"${vctools_dir}\""
        "SHELL:/winsdkdir \"${windows_sdk_dir}\""
        "SHELL:/winsdkversion ${RF_MSVC_UCRTVersion}"
    )
    target_link_options(rawframe_compiler_policy INTERFACE
        "/libpath:${vctools_dir}/lib/x64"
        "/libpath:${windows_sdk_dir}/Lib/${RF_MSVC_UCRTVersion}/ucrt/x64"
        "/libpath:${windows_sdk_dir}/Lib/${RF_MSVC_UCRTVersion}/um/x64"
    )
endfunction()
