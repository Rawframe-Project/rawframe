include_guard(GLOBAL)

# What configure still asks about the repository, and nothing more.
#
# TASK-0001 put eleven checks here because there was nowhere else to put them.
# TASK-0010 lands `rf-archcheck`, which owns architecture conformance, and
# ADR-0077 requires that the checks it subsumes are retired in the same change
# so that no second check authority persists. Six were retired: the schema
# version (RA1001 through the schema oracle), the exact tool membership and tool
# identity (RA1004 and RA2006), the CMake target identity (RA1004), and the
# evidence-index naming (RA1003).
#
# The five that remain answer one question: can CMake construct targets at all.
# The index exists, is not absurd, the manifests it lists are there, none of
# them escapes the root, and the evidence index it registers is present. Those
# are statements about reachability, not about correctness, and CMake genuinely
# cannot proceed without them. A check on reachability is not a competing
# authority on architecture, which is why these stay and the other six went.
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

    string(JSON tool_count ERROR_VARIABLE tools_error LENGTH "${repository_json}" tools)
    if(tools_error)
        message(FATAL_ERROR "RF1006 repository index carries no readable tools array")
    endif()

    math(EXPR tool_last "${tool_count} - 1")
    foreach(index RANGE 0 ${tool_last})
        string(JSON tool_manifest GET "${repository_json}" tools ${index})
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
    endforeach()

    # Maintained evidence membership is one registered index. Configure only
    # proves the registration resolves to a file that is there; every semantic
    # proof about what it lists belongs to rf-evidence, and every structural
    # proof about where it may live belongs to rf-archcheck. Two authorities for
    # one property is the thing this repository does not do.
    string(JSON evidence_index ERROR_VARIABLE evidence_index_error GET "${repository_json}" evidenceIndex)
    if(evidence_index_error)
        message(FATAL_ERROR "RF1011 repository index registers no evidence index")
    endif()

    set(evidence_index_path "${CMAKE_SOURCE_DIR}/${evidence_index}")
    if(NOT EXISTS "${evidence_index_path}")
        message(FATAL_ERROR "RF1011 registered evidence index is missing: ${evidence_index}")
    endif()
endfunction()
