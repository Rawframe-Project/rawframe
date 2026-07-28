include_guard(GLOBAL)

# The offline signature-chain fixtures verify release primaries whose trust is a
# property of the artifact bytes rather than of the host running the check. Some
# of those artifacts therefore belong to no host closure, so nothing published
# them and the fixtures could only run where a developer had staged them by
# hand. Membership is declared in the artifact lock as `verificationCorpus` and
# resolved here, so the corpus is acquired once by an explicit sync and read
# from the content-addressed store during test, never from the network.

include("${CMAKE_CURRENT_LIST_DIR}/../bootstrap/verifier.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/authority.cmake")

set(RF_SYNC_VERIFICATION_CORPUS_COUNT 11)

function(rf_sync_collect_verification_corpus repository_root output_ids)
    rf_read_bounded_json("${repository_root}/third_party/artifacts.lock.json" artifact_json)
    string(JSON member_count LENGTH "${artifact_json}" verificationCorpus)
    set(ids "")
    math(EXPR member_last "${member_count} - 1")
    foreach(index RANGE 0 ${member_last})
        string(JSON id GET "${artifact_json}" verificationCorpus ${index})
        list(APPEND ids "${id}")
    endforeach()

    list(LENGTH ids id_count)
    set(unique_ids "${ids}")
    list(REMOVE_DUPLICATES unique_ids)
    list(LENGTH unique_ids unique_count)
    if(NOT id_count EQUAL ${RF_SYNC_VERIFICATION_CORPUS_COUNT} OR NOT unique_count EQUAL id_count)
        rf_bootstrap_fail("RF1575"
            "verification corpus membership is not exactly ${RF_SYNC_VERIFICATION_CORPUS_COUNT} distinct artifacts")
    endif()

    # Membership names artifacts; it may not invent them. `rf_load_artifact`
    # fails closed on an identity the lock does not define.
    foreach(artifact_id IN LISTS ids)
        rf_load_artifact("${repository_root}" "${artifact_id}" declared)
    endforeach()
    set(${output_ids} "${ids}" PARENT_SCOPE)
endfunction()

# Sync-side. Acquires every declared corpus artifact that the store does not
# already hold and publishes it under its verified digest. Idempotent: a second
# run performs no transport work.
function(rf_sync_publish_verification_corpus repository_root host_id transport)
    rf_sync_collect_verification_corpus("${repository_root}" corpus_ids)
    set(acquired 0)
    foreach(artifact_id IN LISTS corpus_ids)
        rf_load_artifact("${repository_root}" "${artifact_id}" locked)
        string(SUBSTRING "${locked_sha256}" 0 2 prefix)
        set(published "${repository_root}/out/cache/objects/${prefix}/${locked_sha256}")
        if(EXISTS "${published}")
            rf_verify_file_identity("${published}" "${locked_byteSize}" "${locked_sha256}"
                "published corpus ${artifact_id}")
            continue()
        endif()
        rf_sync_acquire_artifact(
            "${repository_root}" "${host_id}" "${transport}" "${artifact_id}" acquired_artifact)
        rf_publish_locked_artifact(
            "${repository_root}" "${repository_root}/out/cache" "${artifact_id}" "${acquired_artifact_path}")
        math(EXPR acquired "${acquired} + 1")
    endforeach()
    message(STATUS
        "RF1576 verification corpus complete: ${RF_SYNC_VERIFICATION_CORPUS_COUNT} artifacts, ${acquired} newly acquired")
endfunction()

# Test-side. Resolves one corpus artifact from the content-addressed store and
# verifies its exact identity. It has no transport argument and no fallback, so
# a fixture using it cannot reach the network or an unpublished staging area.
function(rf_sync_require_corpus_artifact repository_root artifact_id output_prefix)
    rf_load_artifact("${repository_root}" "${artifact_id}" locked)
    string(SUBSTRING "${locked_sha256}" 0 2 prefix)
    set(path "${repository_root}/out/cache/objects/${prefix}/${locked_sha256}")
    if(NOT EXISTS "${path}")
        rf_bootstrap_fail("RF1577"
            "verification corpus artifact ${artifact_id} is not published; run the sync stage that publishes it")
    endif()
    rf_verify_file_identity("${path}" "${locked_byteSize}" "${locked_sha256}" "corpus ${artifact_id}")
    set(${output_prefix}_path "${path}" PARENT_SCOPE)
    set(${output_prefix}_sha256 "${locked_sha256}" PARENT_SCOPE)
    set(${output_prefix}_byteSize "${locked_byteSize}" PARENT_SCOPE)
endfunction()
