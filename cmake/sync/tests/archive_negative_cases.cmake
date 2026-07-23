cmake_minimum_required(VERSION 4.4.0)

# Hostile-input archive cases. Every case must fail inside the bounded archive
# validator with its exact RF diagnostic before any extraction is published.
# CTest asserts the code through PASS_REGULAR_EXPRESSION, so this script only
# invokes the production validator against a committed hostile fixture.

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_CASE RF_SCRATCH)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1530 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")

set(fixtures "${RF_REPOSITORY_ROOT}/tools/rf_evidence/tests/fixtures/archives")
set(case_scratch "${RF_SCRATCH}/${RF_CASE}")
file(REMOVE_RECURSE "${case_scratch}")
file(MAKE_DIRECTORY "${case_scratch}")

if(RF_CASE STREQUAL "traversal")
    rf_validate_archive_listing("${fixtures}/traversal.zip" "a")
elseif(RF_CASE STREQUAL "unc")
    rf_validate_archive_listing("${fixtures}/unc.zip" "server")
elseif(RF_CASE STREQUAL "long_name")
    rf_validate_archive_listing("${fixtures}/long_name.zip" "root")
elseif(RF_CASE STREQUAL "colon")
    rf_validate_archive_listing("${fixtures}/colon.zip" "c")
elseif(RF_CASE STREQUAL "absolute")
    rf_validate_archive_listing("${fixtures}/absolute.zip" "evil.txt")
elseif(RF_CASE STREQUAL "case_collision")
    rf_validate_archive_listing("${fixtures}/case_collision.zip" "root")
elseif(RF_CASE STREQUAL "duplicate")
    rf_validate_archive_listing("${fixtures}/duplicate.zip" "root")
elseif(RF_CASE STREQUAL "deep")
    rf_validate_archive_listing("${fixtures}/deep.zip" "d")
elseif(RF_CASE STREQUAL "long_component")
    rf_validate_archive_listing("${fixtures}/long_component.zip" "root")
elseif(RF_CASE STREQUAL "unexpected_root")
    rf_validate_archive_listing("${fixtures}/unexpected_root.zip" "good")
elseif(RF_CASE STREQUAL "missing_root")
    rf_validate_archive_listing("${fixtures}/multiroot.zip" "alpha;beta;gamma")
elseif(RF_CASE STREQUAL "mixed_top")
    rf_validate_rootless_archive_listing("${fixtures}/mixed_top.zip" 2 1 1)
elseif(RF_CASE STREQUAL "rootless_entry_count")
    rf_validate_rootless_archive_listing("${fixtures}/benign.zip" 4 1 1)
elseif(RF_CASE STREQUAL "rootless_shape")
    rf_validate_rootless_archive_listing("${fixtures}/benign.zip" 3 2 0)
elseif(RF_CASE STREQUAL "rootless_destination_exists")
    file(MAKE_DIRECTORY "${case_scratch}/occupied")
    rf_extract_rootless_quarantine("${fixtures}/benign.zip" 3 1 1 "${case_scratch}/occupied")
elseif(RF_CASE STREQUAL "single_multi_entry")
    rf_extract_single_file_archive("${fixtures}/single_pair.zip" "tool.exe" 22
        "f15760c6cedaa7d2c1ab8e073f01e007c873749d3645ef3736eba7730dc4cf24"
        "${case_scratch}/publish" published_file)
elseif(RF_CASE STREQUAL "single_corrupt_payload")
    rf_extract_single_file_archive("${fixtures}/corrupt_single.zip" "tool.exe" 22
        "f15760c6cedaa7d2c1ab8e073f01e007c873749d3645ef3736eba7730dc4cf24"
        "${case_scratch}/publish" published_file)
elseif(RF_CASE STREQUAL "symlink_escape")
    # The fixture's entry names are clean, so listing validation passes by
    # design; the symlink target resolving outside the quarantine is only
    # observable to the post-extraction REAL_PATH containment sweep. Symlink
    # materialization needs a native Linux host, so only that lane registers
    # this case.
    rf_extract_quarantine("${fixtures}/symlink_escape.tar" "root"
        "${case_scratch}/publish")
else()
    message(FATAL_ERROR "RF1531 unknown hostile archive case: ${RF_CASE}")
endif()

message(FATAL_ERROR "RF1532 hostile archive case '${RF_CASE}' unexpectedly passed validation")
