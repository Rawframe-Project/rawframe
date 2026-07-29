include_guard(GLOBAL)

function(rawframe_validate_repository_authority)
    set(repository_index "${CMAKE_SOURCE_DIR}/repository.json")
    if(NOT EXISTS "${repository_index}")
        message(FATAL_ERROR "RF1001 repository index is missing: ${repository_index}")
    endif()

    file(READ "${repository_index}" repository_json LIMIT 1048577)
    string(LENGTH "${repository_json}" repository_bytes)
    if(repository_bytes GREATER 1048576)
        message(FATAL_ERROR "RF1002 repository index exceeds 1048576 bytes")
    endif()

    string(JSON schema_version ERROR_VARIABLE schema_error GET "${repository_json}" schemaVersion)
    if(schema_error OR NOT schema_version EQUAL 4)
        message(FATAL_ERROR "RF1003 repository schemaVersion must be exactly 4")
    endif()

    string(JSON tool_count ERROR_VARIABLE tools_error LENGTH "${repository_json}" tools)
    if(tools_error OR NOT tool_count EQUAL 1)
        message(FATAL_ERROR "RF1004 repository.tools must contain exactly the admitted TASK-0001 tool")
    endif()

    string(JSON tool_manifest GET "${repository_json}" tools 0)
    if(NOT tool_manifest STREQUAL "tools/rf_evidence/tool.json")
        message(FATAL_ERROR "RF1005 unexpected repository tool membership: ${tool_manifest}")
    endif()

    set(tool_path "${CMAKE_SOURCE_DIR}/${tool_manifest}")
    if(NOT EXISTS "${tool_path}")
        message(FATAL_ERROR "RF1006 listed tool manifest is missing: ${tool_manifest}")
    endif()

    file(REAL_PATH "${tool_path}" tool_real BASE_DIRECTORY "${CMAKE_SOURCE_DIR}")
    file(REAL_PATH "${CMAKE_SOURCE_DIR}" repository_real)
    cmake_path(IS_PREFIX repository_real "${tool_real}" NORMALIZE is_owned)
    if(NOT is_owned)
        message(FATAL_ERROR "RF1007 listed tool path escapes the repository: ${tool_manifest}")
    endif()

    file(READ "${tool_path}" tool_json LIMIT 1048577)
    string(JSON tool_id ERROR_VARIABLE tool_id_error GET "${tool_json}" id)
    string(JSON tool_target ERROR_VARIABLE tool_target_error GET "${tool_json}" implementation cmakeTarget)
    if(tool_id_error OR NOT tool_id STREQUAL "rawframe.tool.evidence")
        message(FATAL_ERROR "RF1008 TASK-0001 tool ID must be rawframe.tool.evidence")
    endif()
    if(tool_target_error OR NOT tool_target STREQUAL "rawframe_tool_rf_evidence")
        message(FATAL_ERROR "RF1009 TASK-0001 CMake target identity is invalid")
    endif()

    # Maintained evidence membership is one registered index. Configure only
    # proves the registration exists and resolves inside the repository; every
    # semantic proof about what it lists belongs to rf-evidence, which is the
    # authority for it. Two authorities for one property is the thing this
    # repository does not do.
    string(JSON evidence_index ERROR_VARIABLE evidence_index_error GET "${repository_json}" evidenceIndex)
    if(evidence_index_error OR NOT evidence_index STREQUAL "evidence/evidence.json")
        message(FATAL_ERROR "RF1010 repository.evidenceIndex must name evidence/evidence.json")
    endif()

    set(evidence_index_path "${CMAKE_SOURCE_DIR}/${evidence_index}")
    if(NOT EXISTS "${evidence_index_path}")
        message(FATAL_ERROR "RF1011 registered evidence index is missing: ${evidence_index}")
    endif()

    set(RAWFRAME_EVIDENCE_TOOL_TARGET "${tool_target}" PARENT_SCOPE)
endfunction()
