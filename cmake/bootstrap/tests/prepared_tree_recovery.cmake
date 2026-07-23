cmake_minimum_required(VERSION 4.4.0)

# Crash and fault-injection coverage for the bounded fail-closed
# prepared-tree rollback recovery accepted by the 2026-07-16 TASK-0001
# amendment. The harness fabricates the exact on-disk states an interrupted
# republish can leave behind, runs the publisher in a child process, and
# asserts both the diagnostic and that a refused recovery deleted nothing.
# The registration is identical on the Windows and Linux lanes.

if(DEFINED RF_MODE AND RF_MODE STREQUAL "publish")
    foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_SOURCE RF_DESTINATION RF_MARKER_FILE)
        if(NOT DEFINED ${argument})
            message(FATAL_ERROR "RF1551 ${argument} is required")
        endif()
    endforeach()
    include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
    include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/verifier.cmake")
    file(READ "${RF_MARKER_FILE}" marker_content)
    if(DEFINED RF_RECOVERY_ROOT)
        rf_publish_prepared_tree("${RF_SOURCE}" "${RF_DESTINATION}" "${marker_content}" "${RF_RECOVERY_ROOT}")
    else()
        rf_publish_prepared_tree("${RF_SOURCE}" "${RF_DESTINATION}" "${marker_content}")
    endif()
    message(STATUS "RF1552 publish completed")
    return()
endif()

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_CASE RF_SCRATCH)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1551 ${argument} is required")
    endif()
endforeach()

set(sandbox "${RF_SCRATCH}/${RF_CASE}")
file(REMOVE_RECURSE "${sandbox}")
set(recovery_root "${sandbox}/prepared")
set(destination "${recovery_root}/tools/fixture")
set(source "${sandbox}/source")
file(MAKE_DIRECTORY "${recovery_root}/tools" "${source}")
file(WRITE "${source}/payload.txt" "generation-two payload\n")
set(marker "{\n  \"host\": \"fixture\",\n  \"tool\": \"tool.fixture\",\n  \"verifierContractVersion\": 1\n}\n")
set(marker_file "${sandbox}/marker.json")
file(WRITE "${marker_file}" "${marker}")
set(other_marker_file "${sandbox}/marker-other.json")
file(WRITE "${other_marker_file}"
    "{\n  \"host\": \"fixture\",\n  \"tool\": \"tool.other\",\n  \"verifierContractVersion\": 1\n}\n")

function(rf_run_publish result_variable output_variable marker_path use_recovery_root)
    set(recovery_arguments "")
    if(use_recovery_root)
        set(recovery_arguments "-DRF_RECOVERY_ROOT=${recovery_root}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            "-DRF_MODE=publish"
            "-DRF_REPOSITORY_ROOT=${RF_REPOSITORY_ROOT}"
            "-DRF_SOURCE=${source}"
            "-DRF_DESTINATION=${destination}"
            "-DRF_MARKER_FILE=${marker_path}"
            ${recovery_arguments}
            -P "${CMAKE_CURRENT_LIST_FILE}"
        RESULT_VARIABLE child_result
        OUTPUT_VARIABLE child_output
        ERROR_VARIABLE child_error
        TIMEOUT 60
    )
    set(${result_variable} "${child_result}" PARENT_SCOPE)
    set(${output_variable} "${child_output}${child_error}" PARENT_SCOPE)
endfunction()

function(rf_require_publish_success marker_path)
    rf_run_publish(publish_result publish_output "${marker_path}" TRUE)
    if(NOT publish_result EQUAL 0)
        message(FATAL_ERROR "RF1553 expected publish to succeed: ${publish_output}")
    endif()
endfunction()

function(rf_require_publish_rf1308 marker_path use_recovery_root)
    rf_run_publish(publish_result publish_output "${marker_path}" ${use_recovery_root})
    if(publish_result EQUAL 0)
        message(FATAL_ERROR "RF1553 expected publish to fail closed, but it succeeded")
    endif()
    string(FIND "${publish_output}" "RF1308" failure_index)
    if(failure_index EQUAL -1)
        message(FATAL_ERROR "RF1553 expected an RF1308 diagnostic: ${publish_output}")
    endif()
endfunction()

function(rf_require_marker_equals tree expected detail)
    file(READ "${tree}/.rf-prepared.json" actual)
    if(NOT actual STREQUAL expected)
        message(FATAL_ERROR "RF1553 ${detail}")
    endif()
endfunction()

if(RF_CASE STREQUAL "fresh_publish")
    rf_require_publish_success("${marker_file}")
    if(NOT EXISTS "${destination}/payload.txt" OR EXISTS "${destination}.previous" OR
       EXISTS "${destination}.incoming")
        message(FATAL_ERROR "RF1553 fresh publish left an unexpected state")
    endif()
    rf_require_marker_equals("${destination}" "${marker}" "fresh publish wrote a wrong marker")

elseif(RF_CASE STREQUAL "stale_previous_clean")
    # Crash window: the interrupted run finished the final rename but died
    # before removing its rollback copy. The destination verifies against the
    # desired identity, so recovery removes the verified-stale tree.
    rf_require_publish_success("${marker_file}")
    file(MAKE_DIRECTORY "${destination}.previous")
    file(WRITE "${destination}.previous/stale.txt" "generation-one leftover\n")
    file(WRITE "${source}/payload.txt" "generation-three payload\n")
    rf_require_publish_success("${marker_file}")
    if(EXISTS "${destination}.previous" OR EXISTS "${destination}.incoming")
        message(FATAL_ERROR "RF1553 verified-stale rollback state survived recovery")
    endif()
    file(READ "${destination}/payload.txt" payload)
    if(NOT payload STREQUAL "generation-three payload\n")
        message(FATAL_ERROR "RF1553 republish did not deliver the new payload")
    endif()

elseif(RF_CASE STREQUAL "restore_previous")
    # Crash window: the interrupted run staged the old tree as .previous and
    # died before the final rename. The single fully verified rollback tree
    # is restored, then replaced atomically by the republish.
    rf_require_publish_success("${marker_file}")
    file(RENAME "${destination}" "${destination}.previous")
    rf_require_publish_success("${marker_file}")
    if(NOT EXISTS "${destination}/payload.txt" OR EXISTS "${destination}.previous")
        message(FATAL_ERROR "RF1553 restore did not leave one published tree")
    endif()
    rf_require_marker_equals("${destination}" "${marker}" "restored publish wrote a wrong marker")

elseif(RF_CASE STREQUAL "identity_mismatch")
    rf_require_publish_success("${marker_file}")
    file(MAKE_DIRECTORY "${destination}.previous")
    file(WRITE "${destination}.previous/stale.txt" "leftover\n")
    rf_require_publish_rf1308("${other_marker_file}" TRUE)
    if(NOT EXISTS "${destination}/payload.txt" OR NOT EXISTS "${destination}.previous/stale.txt")
        message(FATAL_ERROR "RF1553 refused recovery must delete nothing")
    endif()
    rf_require_marker_equals("${destination}" "${marker}" "refused recovery altered the destination")

elseif(RF_CASE STREQUAL "mismatched_restore")
    rf_require_publish_success("${marker_file}")
    file(RENAME "${destination}" "${destination}.previous")
    rf_require_publish_rf1308("${other_marker_file}" TRUE)
    if(EXISTS "${destination}" OR NOT EXISTS "${destination}.previous/payload.txt")
        message(FATAL_ERROR "RF1553 refused restore must choose and delete nothing")
    endif()
    rf_require_marker_equals("${destination}.previous" "${marker}" "refused restore altered the rollback tree")

elseif(RF_CASE STREQUAL "ambiguous_incoming")
    rf_require_publish_success("${marker_file}")
    file(MAKE_DIRECTORY "${destination}.previous" "${destination}.incoming")
    file(WRITE "${destination}.previous/stale.txt" "leftover\n")
    file(WRITE "${destination}.incoming/partial.txt" "interrupted copy\n")
    rf_require_publish_rf1308("${marker_file}" TRUE)
    if(NOT EXISTS "${destination}.previous/stale.txt" OR NOT EXISTS "${destination}.incoming/partial.txt")
        message(FATAL_ERROR "RF1553 ambiguous state must be left untouched")
    endif()

elseif(RF_CASE STREQUAL "no_recovery_root")
    # Publications without an accepted recovery root keep the strict
    # pre-amendment behavior for any rollback leftover.
    rf_require_publish_success("${marker_file}")
    file(MAKE_DIRECTORY "${destination}.previous")
    file(WRITE "${destination}.previous/stale.txt" "leftover\n")
    rf_require_publish_rf1308("${marker_file}" FALSE)
    if(NOT EXISTS "${destination}/payload.txt" OR NOT EXISTS "${destination}.previous/stale.txt")
        message(FATAL_ERROR "RF1553 strict mode must delete nothing")
    endif()

elseif(RF_CASE STREQUAL "corrupt_marker")
    file(MAKE_DIRECTORY "${destination}.previous")
    file(WRITE "${destination}.previous/orphan.txt" "no marker was ever written\n")
    rf_require_publish_rf1308("${marker_file}" TRUE)
    if(NOT EXISTS "${destination}.previous/orphan.txt")
        message(FATAL_ERROR "RF1553 unverifiable rollback state must be left untouched")
    endif()

elseif(RF_CASE STREQUAL "containment_escape")
    set(destination "${sandbox}/outside/fixture")
    file(MAKE_DIRECTORY "${sandbox}/outside")
    rf_require_publish_success("${marker_file}")
    file(MAKE_DIRECTORY "${destination}.previous")
    file(WRITE "${destination}.previous/stale.txt" "leftover\n")
    rf_require_publish_rf1308("${marker_file}" TRUE)
    if(NOT EXISTS "${destination}/payload.txt" OR NOT EXISTS "${destination}.previous/stale.txt")
        message(FATAL_ERROR "RF1553 out-of-root recovery must delete nothing")
    endif()

elseif(RF_CASE STREQUAL "link_indirection")
    rf_require_publish_success("${marker_file}")
    set(elsewhere "${sandbox}/elsewhere")
    file(MAKE_DIRECTORY "${elsewhere}")
    file(WRITE "${elsewhere}/canary.txt" "must survive\n")
    file(CREATE_LINK "${elsewhere}" "${destination}.previous" SYMBOLIC RESULT link_result)
    if(NOT link_result EQUAL 0)
        message(STATUS "RF1550 prepared-tree recovery case '${RF_CASE}' passed (skipped: symbolic links are unavailable on this host)")
        return()
    endif()
    rf_require_publish_rf1308("${marker_file}" TRUE)
    if(NOT EXISTS "${elsewhere}/canary.txt" OR NOT IS_SYMLINK "${destination}.previous")
        message(FATAL_ERROR "RF1553 link indirection must stop recovery without deletion")
    endif()

else()
    message(FATAL_ERROR "RF1551 unknown prepared-tree recovery case: ${RF_CASE}")
endif()

message(STATUS "RF1550 prepared-tree recovery case '${RF_CASE}' passed")
