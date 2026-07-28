cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_HOST)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1496 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/openpgp.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/verification_corpus.cmake")
rf_sync_require_prepared_verifiers("${RF_REPOSITORY_ROOT}" "${RF_HOST}" gpg gpgv cosign trusted_root)
set(work_root "${RF_REPOSITORY_ROOT}/out/sync/${RF_HOST}/quarantine")
file(MAKE_DIRECTORY "${work_root}")

# This fixture verifies release-primary signature chains offline. It takes no
# transport at all: every input is a declared verification-corpus artifact that
# an explicit sync has already published to the content-addressed store, so the
# fixture cannot reach the network even by mistake. A missing input names the
# artifact and the stage that publishes it rather than failing inside a
# transport with an opaque status.
set(covered_ids "")
foreach(pair IN ITEMS
        "tool.vcpkg.linux_x86_64|vcpkg"
        "tool.vcpkg.linux_x86_64_signature|vcpkg_signature"
        "authority.microsoft_release_key.data|microsoft_key"
        "library.openssl.source|openssl"
        "library.openssl.source_signature|openssl_signature"
        "authority.openssl_release_keys.data|openssl_keys"
        "tool.jsonschema_oracle.windows_x86_64|oracle_windows"
        "tool.jsonschema_oracle.linux_x86_64|oracle_linux"
        "tool.jsonschema_oracle.checksums|oracle_checksums"
        "tool.jsonschema_oracle.checksums_signature|oracle_signature"
        "authority.sourcemeta_release_key.data|sourcemeta_key")
    string(REPLACE "|" ";" fields "${pair}")
    list(GET fields 0 artifact_id)
    list(GET fields 1 prefix)
    rf_sync_require_corpus_artifact("${RF_REPOSITORY_ROOT}" "${artifact_id}" ${prefix})
    list(APPEND covered_ids "${artifact_id}")
endforeach()

# What this fixture reads must be exactly what the lock declares. Without this,
# declaring a twelfth corpus artifact would publish it and verify nothing, and
# dropping one from the declaration would silently end its coverage here.
rf_sync_collect_verification_corpus("${RF_REPOSITORY_ROOT}" declared_ids)
list(SORT declared_ids)
list(SORT covered_ids)
if(NOT declared_ids STREQUAL covered_ids)
    rf_bootstrap_fail("RF1578" "declared verification corpus and fixture coverage differ")
endif()

rf_prepare_release_keyring(
    "${gpg}" "${microsoft_key_path}" "BC528686B50D79E339D3721CEB3E94ADBE1229CF"
    "${work_root}" "microsoft" microsoft_keyring
)
rf_verify_detached_openpgp(
    "${gpgv}" "${microsoft_keyring}" "${vcpkg_signature_path}" "${vcpkg_path}"
    "BC528686B50D79E339D3721CEB3E94ADBE1229CF" "vcpkg 2026.07.13 Linux tool"
)

rf_prepare_release_keyring(
    "${gpg}" "${openssl_keys_path}" "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF"
    "${work_root}" "openssl" openssl_keyring
)
rf_verify_detached_openpgp(
    "${gpgv}" "${openssl_keyring}" "${openssl_signature_path}" "${openssl_path}"
    "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF" "OpenSSL 3.5.7 source"
)

rf_prepare_release_keyring(
    "${gpg}" "${sourcemeta_key_path}" "F1CCCE7BD9D52CB76FE05C9B9C6328B7F7D5AA04"
    "${work_root}" "sourcemeta" sourcemeta_keyring
)
rf_verify_detached_openpgp(
    "${gpgv}" "${sourcemeta_keyring}" "${oracle_signature_path}" "${oracle_checksums_path}"
    "74349365D546399E77BE3943C92F4034F60CEC38" "Sourcemeta v16.1.0 checksums"
)
rf_require_exact_checksum_line(
    "${oracle_checksums_path}"
    "SHA256 (jsonschema-16.1.0-windows-x86_64.zip) = ${oracle_windows_sha256}"
    "Sourcemeta Windows oracle"
)
rf_require_exact_checksum_line(
    "${oracle_checksums_path}"
    "SHA256 (jsonschema-16.1.0-linux-x86_64.zip) = ${oracle_linux_sha256}"
    "Sourcemeta Linux oracle"
)
message(STATUS "RF1497 release-primary OpenPGP fixtures passed from the published corpus")
