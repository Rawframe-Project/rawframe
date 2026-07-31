include_guard(GLOBAL)

# Reads one string array out of a maintained JSON authority and reports whether
# it carries an exact value. The membership arrays and the instrumentation
# manifest are the authority for what this lane may do, so the answer is read
# from them rather than repeated here, where it would become a second truth.
function(rawframe_json_array_contains out_variable json_text array_pointer wanted)
    set(found NO)
    string(JSON array_length ERROR_VARIABLE json_error LENGTH "${json_text}" ${array_pointer})
    if(json_error)
        message(FATAL_ERROR "RF1130 ${array_pointer} is not a readable array: ${json_error}")
    endif()
    if(array_length GREATER 0)
        math(EXPR last_index "${array_length} - 1")
        foreach(index RANGE ${last_index})
            string(JSON entry GET "${json_text}" ${array_pointer} ${index})
            if(entry STREQUAL "${wanted}")
                set(found YES)
                break()
            endif()
        endforeach()
    endif()
    set(${out_variable} ${found} PARENT_SCOPE)
endfunction()

# The build configuration is selected, never inferred. SPEC-0003 fixes exactly
# three, each one a maintained authority listed in the repository index, and a
# configure that did not name one would be a fourth configuration with no
# document behind it.
function(rawframe_validate_selected_configuration)
    if(NOT DEFINED RAWFRAME_CONFIGURATION OR RAWFRAME_CONFIGURATION STREQUAL "")
        message(FATAL_ERROR "RF1131 RAWFRAME_CONFIGURATION must come from a committed preset")
    endif()
    if(NOT RAWFRAME_CONFIGURATION MATCHES "^build\\.(debug|development|shipping)$")
        message(FATAL_ERROR
            "RF1132 RAWFRAME_CONFIGURATION must be one of the three SPEC-0003 configurations; "
            "observed ${RAWFRAME_CONFIGURATION}")
    endif()

    file(READ "${CMAKE_SOURCE_DIR}/repository.json" repository_index)
    rawframe_json_array_contains(listed "${repository_index}" configurations
        "targets/configurations/${RAWFRAME_CONFIGURATION}.json")
    if(NOT listed)
        message(FATAL_ERROR
            "RF1133 the root repository index does not list ${RAWFRAME_CONFIGURATION} as a configuration authority")
    endif()
endfunction()

# The one instrumentation policy this repository has a consumer for. ADR-0006
# makes instrumentation a lane over a configuration and never a configuration of
# its own, so this adds flags to the selected configuration and changes nothing
# else about it.
function(rawframe_apply_instrumentation_policy target_name)
    if(NOT DEFINED RAWFRAME_INSTRUMENTATION OR RAWFRAME_INSTRUMENTATION STREQUAL "")
        return()
    endif()
    if(NOT RAWFRAME_INSTRUMENTATION STREQUAL "instrumentation.coverage")
        message(FATAL_ERROR
            "RF1134 the only instrumentation with a definition in this repository is instrumentation.coverage; "
            "observed ${RAWFRAME_INSTRUMENTATION}")
    endif()

    set(manifest_path "${CMAKE_SOURCE_DIR}/targets/instrumentations/instrumentation.coverage.json")
    file(READ "${CMAKE_SOURCE_DIR}/repository.json" repository_index)
    rawframe_json_array_contains(listed "${repository_index}" instrumentations
        "targets/instrumentations/instrumentation.coverage.json")
    if(NOT listed)
        message(FATAL_ERROR "RF1135 the root repository index does not list the coverage instrumentation authority")
    endif()

    file(READ "${manifest_path}" instrumentation_manifest)
    rawframe_json_array_contains(configuration_ok "${instrumentation_manifest}"
        compatibleConfigurations "${RAWFRAME_CONFIGURATION}")
    if(NOT configuration_ok)
        message(FATAL_ERROR
            "RF1136 instrumentation.coverage does not declare ${RAWFRAME_CONFIGURATION} compatible")
    endif()

    string(REPLACE "-" "_" host_family_suffix "${RAWFRAME_HOST_ID}")
    rawframe_json_array_contains(family_ok "${instrumentation_manifest}"
        platformFamilies "host.${host_family_suffix}")
    if(NOT family_ok)
        message(FATAL_ERROR
            "RF1137 instrumentation.coverage does not declare host.${host_family_suffix} a supported family")
    endif()

    rawframe_json_array_contains(toolchain_ok "${instrumentation_manifest}" toolchains "compiler.llvm_clang")
    if(NOT toolchain_ok)
        message(FATAL_ERROR "RF1138 instrumentation.coverage does not declare the locked Clang toolchain")
    endif()

    # Source-based coverage, with MC/DC, which STD-0007 requires over the
    # validating path of every Tier H unit. The same three options are given to
    # the link step so the Clang driver brings in its profiling runtime; naming
    # the runtime library here instead would put a toolchain implementation
    # detail in this repository.
    #
    # The raw-profile destination is compiled in rather than left to
    # LLVM_PROFILE_FILE. An instrumented binary with no destination writes
    # `default.profraw` into whatever its working directory happens to be, and
    # the first coverage run proved that at least one spawned process does lose
    # the environment variable: a stray profile landed in the repository root,
    # where the path audit would have reported it as unclassified and where the
    # merge step would never have found it. `%p` is expanded by the profiling
    # runtime to the process ID, which keeps concurrent CTest processes from
    # overwriting each other.
    set(profile_destination "${CMAKE_BINARY_DIR}/coverage-profiles/rf-%p.profraw")
    set(coverage_options "-fprofile-instr-generate=${profile_destination}" -fcoverage-mapping -fcoverage-mcdc)
    target_compile_options(${target_name} INTERFACE ${coverage_options})
    target_link_options(${target_name} INTERFACE ${coverage_options})
endfunction()

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

    rawframe_validate_selected_configuration()

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

    rawframe_apply_instrumentation_policy(rawframe_compiler_policy)

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
        # Both maintained first-party roots. The filter named `tools/` alone
        # while `tools/` was the only first-party tree that existed, which read
        # as a deliberate narrowing and was in fact a description of the
        # repository at the time. PLAN-0002 requires every translation unit
        # analysed, so the production root is admitted here, by the Task that
        # adds the first new translation units since the rule was written.
        set(CMAKE_CXX_CLANG_TIDY
            "${RAWFRAME_CLANG_TIDY_EXECUTABLE};--config-file=${CMAKE_SOURCE_DIR}/.clang-tidy;--header-filter=[\\\\/](source|tools)[\\\\/]${analysis_lane_checks}"
            PARENT_SCOPE)
    endif()
endfunction()
