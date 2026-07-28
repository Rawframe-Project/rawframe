cmake_minimum_required(VERSION 4.4.0)

foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_HOST RF_TRANSPORT)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1496 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/transport.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/authority.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/openpgp.cmake")
rf_sync_require_prepared_verifiers("${RF_REPOSITORY_ROOT}" "${RF_HOST}" gpg gpgv cosign trusted_root)
set(work_root "${RF_REPOSITORY_ROOT}/out/sync/${RF_HOST}/quarantine")

# This fixture verifies release-primary signature chains offline and is given a
# denied transport on purpose, because the dependency contract forbids network
# access during test. Several of its inputs are platform.linux artifacts that a
# Windows sync never publishes, so on a clean Windows host they must be staged
# explicitly. Report exactly which are missing instead of failing later inside
# the transport with an opaque curl status.
set(missing_inputs "")
foreach(required_id IN ITEMS
        "tool.vcpkg.linux_x86_64" "tool.vcpkg.linux_x86_64_signature"
        "authority.microsoft_release_key.data" "library.openssl.source"
        "library.openssl.source_signature" "authority.openssl_release_keys.data"
        "tool.jsonschema_oracle.windows_x86_64" "tool.jsonschema_oracle.linux_x86_64"
        "tool.jsonschema_oracle.checksums" "tool.jsonschema_oracle.checksums_signature"
        "authority.sourcemeta_release_key.data")
    rf_sync_load_artifact("${RF_REPOSITORY_ROOT}" "${required_id}" probe)
    if(NOT EXISTS "${work_root}/artifact-${probe_sha256}"
       AND NOT EXISTS "${RF_REPOSITORY_ROOT}/out/sync/${RF_HOST}/prestaged/artifact-${probe_sha256}")
        list(APPEND missing_inputs "${required_id}")
    endif()
endforeach()
if(missing_inputs)
    list(JOIN missing_inputs ", " missing_text)
    rf_bootstrap_fail("RF1497"
        "release-primary inputs are not staged for ${RF_HOST} and this fixture may not use the network: ${missing_text}")
endif()

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
    rf_sync_acquire_artifact(
        "${RF_REPOSITORY_ROOT}" "${RF_HOST}" "${RF_TRANSPORT}" "${artifact_id}" ${prefix}
    )
endforeach()

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
message(STATUS "RF1497 release-primary OpenPGP fixtures passed without CAS publication")

