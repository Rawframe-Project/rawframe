include_guard(GLOBAL)

function(rawframe_define_compiler_policy)
    if(NOT CMAKE_VERSION VERSION_EQUAL "4.4.0")
        message(FATAL_ERROR "RF1101 CMake must be exactly 4.4.0; observed ${CMAKE_VERSION}")
    endif()

    if(NOT DEFINED RAWFRAME_HOST_ID)
        message(FATAL_ERROR "RF1102 RAWFRAME_HOST_ID must come from a committed TASK-0001 preset")
    endif()

    if(RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
        if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
            message(FATAL_ERROR "RF1103 windows-x86_64 preset is running on the wrong host architecture")
        endif()
        if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
            message(FATAL_ERROR "RF1104 Windows requires the locked clang-cl frontend")
        endif()
    elseif(RAWFRAME_HOST_ID STREQUAL "linux-x86_64")
        if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
            message(FATAL_ERROR "RF1105 linux-x86_64 preset is running on the wrong host architecture")
        endif()
        if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            message(FATAL_ERROR "RF1106 Linux requires the locked Clang frontend")
        endif()
    else()
        message(FATAL_ERROR "RF1107 unsupported RAWFRAME_HOST_ID: ${RAWFRAME_HOST_ID}")
    endif()

    if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_EQUAL "22.1.8")
        message(FATAL_ERROR "RF1108 Clang must be exactly 22.1.8; observed ${CMAKE_CXX_COMPILER_VERSION}")
    endif()

    if(RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
        # The locked x64-windows-rawframe dependency closure is release-only
        # against the dynamic release CRT, so every first-party configuration
        # must select the same runtime to keep one link-compatible ABI.
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" PARENT_SCOPE)
    endif()

    add_library(rawframe_compiler_policy INTERFACE)
    add_library(rawframe::compiler_policy ALIAS rawframe_compiler_policy)
    target_compile_features(rawframe_compiler_policy INTERFACE cxx_std_23)

    if(MSVC)
        target_compile_options(rawframe_compiler_policy INTERFACE
            /W4
            /WX
            /permissive-
            /Zc:__cplusplus
            /EHs-c-
            /GR-
            -clang:-std=c++23
        )
    else()
        target_compile_options(rawframe_compiler_policy INTERFACE
            -Wall
            -Wextra
            -Wpedantic
            -Werror
            -fno-exceptions
            -fno-rtti
            -stdlib=libc++
            -std=c++23
        )
        target_link_options(rawframe_compiler_policy INTERFACE -stdlib=libc++ -fuse-ld=lld)
    endif()

    if(RAWFRAME_ENABLE_ANALYSIS)
        if(NOT DEFINED RAWFRAME_CLANG_TIDY_EXECUTABLE OR
           NOT EXISTS "${RAWFRAME_CLANG_TIDY_EXECUTABLE}")
            message(FATAL_ERROR "RF1109 the preset's locked clang-tidy executable is absent")
        endif()
        # The Task-0001 analysis lane gates maintained first-party paths only;
        # toolset, SDK, and dependency headers are outside this repository's
        # remediation authority, so the invocation narrows the repository
        # configuration's header filter. Repository-wide check policy,
        # including the STD-0002 `#pragma once` suppression, lives in the
        # root `.clang-tidy` per the accepted 2026-07-16 amendment.
        set(analysis_lane_checks "")
        if(RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
            # Windows lane only: clang-analyzer findings ignore the header
            # filter, and the optin.core.EnumCastOutOfRange report fires
            # inside the pinned MSVC standard library, which this repository
            # cannot remediate. The Linux lane keeps the check enabled and is
            # the effective enforcement point for shared first-party sources.
            set(analysis_lane_checks ";--checks=-clang-analyzer-optin.core.EnumCastOutOfRange")
        endif()
        set(CMAKE_CXX_CLANG_TIDY
            "${RAWFRAME_CLANG_TIDY_EXECUTABLE};--config-file=${CMAKE_SOURCE_DIR}/.clang-tidy;--header-filter=[\\\\/]tools[\\\\/]${analysis_lane_checks}"
            PARENT_SCOPE)
    endif()
endfunction()
