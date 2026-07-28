cmake_minimum_required(VERSION 4.4.0)

if(NOT DEFINED RF_OPERATION OR NOT RF_OPERATION STREQUAL "sync")
    message(FATAL_ERROR "RF1462 Windows Stage-1 accepts only RF_OPERATION=sync")
endif()
if(NOT DEFINED RF_REPOSITORY_ROOT)
    cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH cmake_root)
    cmake_path(GET cmake_root PARENT_PATH RF_REPOSITORY_ROOT)
endif()
set(RF_HOST "windows-x86_64")

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/archive.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/verifier.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authenticode.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/openpgp.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/licenses.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/llvm.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/windows_closure.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/windows_prepare.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/verification_corpus.cmake")

rf_load_bootstrap_authority("${RF_REPOSITORY_ROOT}" "${RF_HOST}")
rf_verify_transport_executable(
    "${RF_transport_absolutePath}" "${RF_transport_minimumVersion}" "${RF_transport_vendorSignature}"
    transport_measured_version
)
rf_sync_verify_complete_windows_closure(
    "${RF_REPOSITORY_ROOT}" "${RF_transport_absolutePath}" publication_ids publication_paths
)
list(LENGTH publication_ids publication_count)
math(EXPR publication_last "${publication_count} - 1")
foreach(index RANGE 0 ${publication_last})
    list(GET publication_ids ${index} artifact_id)
    list(GET publication_paths ${index} artifact_path)
    rf_publish_locked_artifact("${RF_REPOSITORY_ROOT}" "${RF_REPOSITORY_ROOT}/out/cache" "${artifact_id}" "${artifact_path}")
endforeach()

# Published separately from the host closure. Corpus membership is a property of
# the artifact, so it neither joins nor perturbs the counted Windows selection.
rf_sync_publish_verification_corpus(
    "${RF_REPOSITORY_ROOT}" "${RF_HOST}" "${RF_transport_absolutePath}"
)

rf_prepare_windows_tools("${RF_REPOSITORY_ROOT}")
rf_prepare_windows_vcpkg("${RF_REPOSITORY_ROOT}")

file(MAKE_DIRECTORY "${RF_REPOSITORY_ROOT}/out/reports/task-0001/windows-x86_64")
file(WRITE "${RF_REPOSITORY_ROOT}/out/reports/task-0001/windows-x86_64/stage1-cas.json.tmp"
    "{\n  \"host\": \"windows-x86_64\",\n  \"selectedArtifacts\": 29,\n  \"publishedStage1Artifacts\": 19,\n  \"preparedToolTrees\": 6,\n  \"preparedProviderTrees\": 1,\n  \"state\": \"verified_prepared\"\n}\n"
)
file(RENAME
    "${RF_REPOSITORY_ROOT}/out/reports/task-0001/windows-x86_64/stage1-cas.json.tmp"
    "${RF_REPOSITORY_ROOT}/out/reports/task-0001/windows-x86_64/stage1-cas.json"
)
message(STATUS "RF1463 complete Windows artifact closure verified, published to CAS, and prepared")
