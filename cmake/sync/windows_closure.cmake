include_guard(GLOBAL)

function(rf_sync_verify_windows_vcpkg repository_root transport output_ids output_paths)
    rf_sync_acquire_artifact("${repository_root}" "windows-x86_64" "${transport}"
        "tool.vcpkg.windows_x86_64" vcpkg_windows)
    set(signtool "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe")
    rf_verify_windows_authenticode(
        "${signtool}" 543144 "e7b517a6a2828af2d1fba3da60ae1e322a95141bfae192622725329630caa2b3"
        "${vcpkg_windows_path}" "1D77A9B9E8FE2075D9AD15123257FB90DB0DA4A1"
        "vcpkg 2026.07.13 Windows tool"
    )
    set(${output_ids} "tool.vcpkg.windows_x86_64" PARENT_SCOPE)
    set(${output_paths} "${vcpkg_windows_path}" PARENT_SCOPE)
endfunction()

function(rf_sync_verify_openssl repository_root transport output_ids output_paths)
    foreach(pair IN ITEMS
            "library.openssl.source|openssl"
            "library.openssl.source_signature|openssl_signature"
            "authority.openssl_release_keys.data|openssl_keys")
        string(REPLACE "|" ";" fields "${pair}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 prefix)
        rf_sync_acquire_artifact("${repository_root}" "windows-x86_64" "${transport}" "${artifact_id}" ${prefix})
    endforeach()
    rf_sync_require_prepared_verifiers("${repository_root}" "windows-x86_64" gpg gpgv cosign trusted_root)
    set(work_root "${repository_root}/out/sync/windows-x86_64/quarantine")
    rf_prepare_release_keyring(
        "${gpg}" "${openssl_keys_path}" "BA5473A2B0587B07FB27CF2D216094DFD0CB81EF"
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

function(rf_sync_verify_windows_oracle repository_root transport output_ids output_paths)
    foreach(pair IN ITEMS
            "tool.jsonschema_oracle.windows_x86_64|oracle"
            "tool.jsonschema_oracle.checksums|checksums"
            "tool.jsonschema_oracle.checksums_signature|checksums_signature"
            "authority.sourcemeta_release_key.data|sourcemeta_key")
        string(REPLACE "|" ";" fields "${pair}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 prefix)
        rf_sync_acquire_artifact("${repository_root}" "windows-x86_64" "${transport}" "${artifact_id}" ${prefix})
    endforeach()
    rf_sync_require_prepared_verifiers("${repository_root}" "windows-x86_64" gpg gpgv cosign trusted_root)
    set(work_root "${repository_root}/out/sync/windows-x86_64/quarantine")
    rf_prepare_release_keyring(
        "${gpg}" "${sourcemeta_key_path}" "F1CCCE7BD9D52CB76FE05C9B9C6328B7F7D5AA04"
        "${work_root}" "sourcemeta" sourcemeta_keyring
    )
    rf_verify_detached_openpgp(
        "${gpgv}" "${sourcemeta_keyring}" "${checksums_signature_path}" "${checksums_path}"
        "74349365D546399E77BE3943C92F4034F60CEC38" "Sourcemeta v16.1.0 checksums"
    )
    rf_require_exact_checksum_line(
        "${checksums_path}"
        "SHA256 (jsonschema-16.1.0-windows-x86_64.zip) = ${oracle_sha256}"
        "Sourcemeta Windows oracle"
    )
    rf_validate_archive_listing("${oracle_path}" "jsonschema-16.1.0-windows-x86_64")
    set(${output_ids}
        "tool.jsonschema_oracle.windows_x86_64;tool.jsonschema_oracle.checksums;tool.jsonschema_oracle.checksums_signature;authority.sourcemeta_release_key.data"
        PARENT_SCOPE)
    set(${output_paths} "${oracle_path};${checksums_path};${checksums_signature_path};${sourcemeta_key_path}"
        PARENT_SCOPE)
endfunction()

function(rf_sync_verify_windows_unsigned repository_root transport output_ids output_paths)
    set(ids
        library.simdjson.source
        registry.vcpkg_builtin.source
        test.googletest.source
        tool.nasm.windows_x86_64
        tool.ninja.windows_x86_64
        tool.perl.windows_x86_64
        tool.powershell.windows_x86_64
    )
    set(paths "")
    foreach(id IN LISTS ids)
        rf_sync_acquire_artifact("${repository_root}" "windows-x86_64" "${transport}" "${id}" artifact)
        list(APPEND paths "${artifact_path}")
        if(id STREQUAL "library.simdjson.source")
            rf_validate_archive_listing("${artifact_path}" "simdjson-4.6.4")
        elseif(id STREQUAL "registry.vcpkg_builtin.source")
            rf_validate_archive_listing("${artifact_path}" "vcpkg-8e8dfb4ba483886936ded5ca201b500b8d8b0096")
        elseif(id STREQUAL "test.googletest.source")
            rf_validate_archive_listing("${artifact_path}" "googletest-1.17.0")
        elseif(id STREQUAL "tool.nasm.windows_x86_64")
            rf_validate_archive_listing("${artifact_path}" "nasm-3.01")
        elseif(id STREQUAL "tool.ninja.windows_x86_64")
            rf_validate_archive_listing("${artifact_path}" "ninja.exe")
        elseif(id STREQUAL "tool.perl.windows_x86_64")
            rf_validate_archive_listing("${artifact_path}"
                "DISTRIBUTIONS.txt;README.txt;c;cpan;data;licenses;perl;portable.perl;portableshell.bat;win32")
        elseif(id STREQUAL "tool.powershell.windows_x86_64")
            rf_validate_rootless_archive_listing("${artifact_path}" 986 18 333)
        endif()
    endforeach()
    set(${output_ids} "${ids}" PARENT_SCOPE)
    set(${output_paths} "${paths}" PARENT_SCOPE)
endfunction()

function(rf_sync_verify_complete_windows_closure repository_root transport output_ids output_paths)
    rf_sync_verify_windows_vcpkg("${repository_root}" "${transport}" vcpkg_ids vcpkg_paths)
    rf_sync_verify_openssl("${repository_root}" "${transport}" openssl_ids openssl_paths)
    rf_sync_verify_windows_oracle("${repository_root}" "${transport}" oracle_ids oracle_paths)
    rf_sync_verify_llvm_closure("${repository_root}" "windows-x86_64" "${transport}" llvm_ids llvm_paths)
    rf_validate_archive_listing(
        "${repository_root}/out/sync/windows-x86_64/quarantine/artifact-d96c2cc1736f4eb7fa43cb9bbdf56d93551a9ae0a9aadb9c99c3c3b2b712a234"
        "clang+llvm-22.1.8-x86_64-pc-windows-msvc"
    )
    rf_sync_verify_windows_unsigned("${repository_root}" "${transport}" unsigned_ids unsigned_paths)
    rf_sync_verify_license_closure("${repository_root}")

    set(ids "${vcpkg_ids};${openssl_ids};${oracle_ids};${llvm_ids};${unsigned_ids}")
    set(paths "${vcpkg_paths};${openssl_paths};${oracle_paths};${llvm_paths};${unsigned_paths}")
    list(LENGTH ids id_count)
    set(unique_ids "${ids}")
    list(REMOVE_DUPLICATES unique_ids)
    list(LENGTH unique_ids unique_count)
    list(LENGTH paths path_count)
    if(NOT id_count EQUAL 19 OR NOT unique_count EQUAL 19 OR NOT path_count EQUAL 19)
        rf_bootstrap_fail("RF1460" "Windows Stage-1 publication set is incomplete or duplicated")
    endif()

    rf_read_bounded_json("${repository_root}/third_party/artifacts.lock.json" artifact_json)
    string(JSON artifact_count LENGTH "${artifact_json}" artifacts)
    set(selected_count 0)
    math(EXPR artifact_last "${artifact_count} - 1")
    foreach(index RANGE 0 ${artifact_last})
        string(JSON platform GET "${artifact_json}" artifacts ${index} platform)
        if(NOT platform STREQUAL "platform.any" AND NOT platform STREQUAL "platform.windows")
            continue()
        endif()
        math(EXPR selected_count "${selected_count} + 1")
        string(JSON id GET "${artifact_json}" artifacts ${index} id)
        string(JSON bytes GET "${artifact_json}" artifacts ${index} byteSize)
        string(JSON sha256 GET "${artifact_json}" artifacts ${index} sha256)
        set(cache_path "${repository_root}/out/cache/objects")
        string(SUBSTRING "${sha256}" 0 2 prefix)
        set(path "${cache_path}/${prefix}/${sha256}")
        if(NOT EXISTS "${path}")
            set(path "${repository_root}/out/sync/windows-x86_64/quarantine/artifact-${sha256}")
        endif()
        rf_verify_file_identity("${path}" "${bytes}" "${sha256}" "selected Windows closure artifact ${id}")
    endforeach()
    if(NOT selected_count EQUAL 29)
        rf_bootstrap_fail("RF1461" "Windows host selection does not contain exactly 29 artifacts")
    endif()
    set(${output_ids} "${ids}" PARENT_SCOPE)
    set(${output_paths} "${paths}" PARENT_SCOPE)
endfunction()

