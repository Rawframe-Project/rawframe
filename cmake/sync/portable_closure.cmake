include_guard(GLOBAL)

# Artifacts whose verification is identical on every admitted host. Their trust
# is a property of the bytes and of a publisher signature, not of the machine
# running the check, so each is verified here once and called by both host
# lanes. Host-specific mechanics (Authenticode, Debian package identity, the
# per-host tool archives) stay in the lane that owns them.

function(rf_sync_verify_openssl_source repository_root host_id transport output_ids output_paths)
    foreach(pair IN ITEMS
            "library.openssl.source|openssl"
            "library.openssl.source_signature|openssl_signature"
            "authority.openssl_release_keys.data|openssl_keys")
        string(REPLACE "|" ";" fields "${pair}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 prefix)
        rf_sync_acquire_artifact("${repository_root}" "${host_id}" "${transport}" "${artifact_id}" ${prefix})
    endforeach()
    rf_sync_require_prepared_verifiers("${repository_root}" "${host_id}" gpg gpgv gpgconf cosign trusted_root)
    set(work_root "${repository_root}/out/sync/${host_id}/quarantine")
    rf_prepare_release_keyring(
        "${gpg}" "${gpgconf}" "${openssl_keys_path}" "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF"
        "${work_root}" "openssl" openssl_keyring
    )
    rf_verify_detached_openpgp(
        "${gpgv}" "${openssl_keyring}" "${openssl_signature_path}" "${openssl_path}"
        "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF" "OpenSSL 3.5.7 source"
    )
    rf_validate_archive_listing("${openssl_path}" "openssl-3.5.7")
    set(${output_ids}
        "library.openssl.source;library.openssl.source_signature;authority.openssl_release_keys.data" PARENT_SCOPE)
    set(${output_paths} "${openssl_path};${openssl_signature_path};${openssl_keys_path}" PARENT_SCOPE)
endfunction()

# The Sourcemeta checksum manifest covers every published platform binary, so
# the signed document and its key are shared and only the selected artifact and
# its archive root differ per host.
function(rf_sync_verify_schema_oracle repository_root host_id transport output_ids output_paths)
    if(host_id STREQUAL "windows-x86_64")
        set(oracle_id "tool.jsonschema_oracle.windows_x86_64")
        set(oracle_name "jsonschema-16.1.0-windows-x86_64.zip")
        set(oracle_root "jsonschema-16.1.0-windows-x86_64")
    elseif(host_id STREQUAL "linux-x86_64")
        set(oracle_id "tool.jsonschema_oracle.linux_x86_64")
        set(oracle_name "jsonschema-16.1.0-linux-x86_64.zip")
        set(oracle_root "jsonschema-16.1.0-linux-x86_64")
    else()
        rf_bootstrap_fail("RF1456" "unsupported schema-oracle sync host")
    endif()
    foreach(pair IN ITEMS
            "${oracle_id}|oracle"
            "tool.jsonschema_oracle.checksums|checksums"
            "tool.jsonschema_oracle.checksums_signature|checksums_signature"
            "authority.sourcemeta_release_key.data|sourcemeta_key")
        string(REPLACE "|" ";" fields "${pair}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 prefix)
        rf_sync_acquire_artifact("${repository_root}" "${host_id}" "${transport}" "${artifact_id}" ${prefix})
    endforeach()
    rf_sync_require_prepared_verifiers("${repository_root}" "${host_id}" gpg gpgv gpgconf cosign trusted_root)
    set(work_root "${repository_root}/out/sync/${host_id}/quarantine")
    rf_prepare_release_keyring(
        "${gpg}" "${gpgconf}" "${sourcemeta_key_path}" "F1CCCE7BD9D52CB76FE05C9B9C6328B7F7D5AA04"
        "${work_root}" "sourcemeta" sourcemeta_keyring
    )
    rf_verify_detached_openpgp(
        "${gpgv}" "${sourcemeta_keyring}" "${checksums_signature_path}" "${checksums_path}"
        "74349365D546399E77BE3943C92F4034F60CEC38" "Sourcemeta v16.1.0 checksums"
    )
    rf_require_exact_checksum_line(
        "${checksums_path}"
        "SHA256 (${oracle_name}) = ${oracle_sha256}"
        "Sourcemeta ${host_id} oracle"
    )
    rf_validate_archive_listing("${oracle_path}" "${oracle_root}")
    set(${output_ids}
        "${oracle_id};tool.jsonschema_oracle.checksums;tool.jsonschema_oracle.checksums_signature;authority.sourcemeta_release_key.data"
        PARENT_SCOPE)
    set(${output_paths} "${oracle_path};${checksums_path};${checksums_signature_path};${sourcemeta_key_path}"
        PARENT_SCOPE)
endfunction()

# Registry and library sources. These publish no accepted detached signature,
# so their compensating controls are immutable tag/commit identity, exact
# origin, exact byte length, SHA-256, and the archive root the lock declares.
function(rf_sync_verify_portable_sources repository_root host_id transport output_ids output_paths)
    set(ids
        library.simdjson.source
        registry.vcpkg_builtin.source
        test.googletest.source
    )
    set(paths "")
    foreach(id IN LISTS ids)
        rf_sync_acquire_artifact("${repository_root}" "${host_id}" "${transport}" "${id}" artifact)
        list(APPEND paths "${artifact_path}")
        if(id STREQUAL "library.simdjson.source")
            rf_validate_archive_listing("${artifact_path}" "simdjson-4.6.4")
        elseif(id STREQUAL "registry.vcpkg_builtin.source")
            rf_validate_archive_listing("${artifact_path}" "vcpkg-8e8dfb4ba483886936ded5ca201b500b8d8b0096")
        elseif(id STREQUAL "test.googletest.source")
            rf_validate_archive_listing("${artifact_path}" "googletest-1.17.0")
        endif()
    endforeach()
    set(${output_ids} "${ids}" PARENT_SCOPE)
    set(${output_paths} "${paths}" PARENT_SCOPE)
endfunction()
