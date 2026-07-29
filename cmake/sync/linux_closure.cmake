include_guard(GLOBAL)

# Verifies the complete locked Linux Stage-1 artifact closure. Artifacts whose
# verification does not depend on the host live in portable_closure.cmake and
# are called from here; this file owns only what is specific to the Linux lane.

# The Linux vcpkg tool ships as a bare ELF binary with a detached OpenPGP
# signature instead of the Authenticode signature the Windows binary carries,
# so the same tool is admitted through a different publisher proof on each host.
function(rf_sync_verify_linux_vcpkg repository_root transport output_ids output_paths)
    foreach(pair IN ITEMS
            "tool.vcpkg.linux_x86_64|vcpkg"
            "tool.vcpkg.linux_x86_64_signature|vcpkg_signature"
            "authority.microsoft_release_key.data|microsoft_key")
        string(REPLACE "|" ";" fields "${pair}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 prefix)
        rf_sync_acquire_artifact("${repository_root}" "linux-x86_64" "${transport}" "${artifact_id}" ${prefix})
    endforeach()
    rf_sync_require_prepared_verifiers("${repository_root}" "linux-x86_64" gpg gpgv gpgconf cosign trusted_root)
    rf_prepare_release_keyring(
        "${gpg}" "${gpgconf}" "${microsoft_key_path}" "BC528686B50D79E339D3721CEB3E94ADBE1229CF"
        "${repository_root}/out/sync/linux-x86_64/quarantine" "microsoft" microsoft_keyring
    )
    rf_verify_detached_openpgp(
        "${gpgv}" "${microsoft_keyring}" "${vcpkg_signature_path}" "${vcpkg_path}"
        "BC528686B50D79E339D3721CEB3E94ADBE1229CF" "vcpkg 2026.07.13 Linux tool"
    )
    set(${output_ids}
        "tool.vcpkg.linux_x86_64;tool.vcpkg.linux_x86_64_signature;authority.microsoft_release_key.data"
        PARENT_SCOPE)
    set(${output_paths} "${vcpkg_path};${vcpkg_signature_path};${microsoft_key_path}" PARENT_SCOPE)
endfunction()

# The release media the admitted host tuple was installed from. Its digest is
# published in a Canonical-signed SHA256SUMS document, and the keyring that
# validates that document is the archive keyring Stage 0 already extracted and
# verified from its locked Debian package.
function(rf_sync_verify_ubuntu_media repository_root transport output_ids output_paths)
    foreach(pair IN ITEMS
            "host.ubuntu.linux_x86_64|image"
            "host.ubuntu.sha256sums|checksums"
            "host.ubuntu.sha256sums_signature|checksums_signature")
        string(REPLACE "|" ";" fields "${pair}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 prefix)
        rf_sync_acquire_artifact("${repository_root}" "linux-x86_64" "${transport}" "${artifact_id}" ${prefix})
    endforeach()
    rf_sync_require_prepared_verifiers("${repository_root}" "linux-x86_64" gpg gpgv gpgconf cosign trusted_root)
    set(archive_keyring
        "${repository_root}/out/prepared/linux-x86_64/tools/gnupg/share/gnupg/ubuntu-archive-keyring.gpg")
    if(NOT EXISTS "${archive_keyring}")
        rf_bootstrap_fail("RF1457" "prepared Ubuntu archive keyring is missing")
    endif()
    rf_verify_detached_openpgp(
        "${gpgv}" "${archive_keyring}" "${checksums_signature_path}" "${checksums_path}"
        "843938DF228D22F7B3742BC0D94AA3F0EFE21092" "Ubuntu 24.04 image checksums"
    )
    rf_require_exact_checksum_line(
        "${checksums_path}"
        "${image_sha256} *ubuntu-24.04-live-server-amd64.iso"
        "Ubuntu 24.04 server image"
    )
    set(${output_ids}
        "host.ubuntu.linux_x86_64;host.ubuntu.sha256sums;host.ubuntu.sha256sums_signature" PARENT_SCOPE)
    set(${output_paths} "${image_path};${checksums_path};${checksums_signature_path}" PARENT_SCOPE)
endfunction()

function(rf_sync_verify_linux_unsigned repository_root transport output_ids output_paths)
    rf_sync_acquire_artifact("${repository_root}" "linux-x86_64" "${transport}"
        "tool.ninja.linux_x86_64" ninja)
    rf_validate_archive_listing("${ninja_path}" "ninja")
    set(${output_ids} "tool.ninja.linux_x86_64" PARENT_SCOPE)
    set(${output_paths} "${ninja_path}" PARENT_SCOPE)
endfunction()

function(rf_sync_verify_complete_linux_closure repository_root transport output_ids output_paths)
    rf_sync_verify_linux_vcpkg("${repository_root}" "${transport}" vcpkg_ids vcpkg_paths)
    rf_sync_verify_openssl_source("${repository_root}" "linux-x86_64" "${transport}" openssl_ids openssl_paths)
    rf_sync_verify_schema_oracle("${repository_root}" "linux-x86_64" "${transport}" oracle_ids oracle_paths)
    rf_sync_verify_llvm_closure("${repository_root}" "linux-x86_64" "${transport}" llvm_ids llvm_paths)
    rf_validate_archive_listing(
        "${repository_root}/out/sync/linux-x86_64/quarantine/artifact-df0e1ecf16caf3489a272a5eea4eec9b0d82878f6477fa309504f918a0006384"
        "LLVM-22.1.8-Linux-X64"
    )
    rf_sync_verify_portable_sources("${repository_root}" "linux-x86_64" "${transport}" source_ids source_paths)
    rf_sync_verify_linux_unsigned("${repository_root}" "${transport}" unsigned_ids unsigned_paths)
    rf_sync_verify_ubuntu_media("${repository_root}" "${transport}" media_ids media_paths)
    rf_sync_verify_license_closure("${repository_root}")

    set(ids "${vcpkg_ids};${openssl_ids};${oracle_ids};${llvm_ids};${source_ids};${unsigned_ids};${media_ids}")
    set(paths
        "${vcpkg_paths};${openssl_paths};${oracle_paths};${llvm_paths};${source_paths};${unsigned_paths};${media_paths}")
    list(LENGTH ids id_count)
    set(unique_ids "${ids}")
    list(REMOVE_DUPLICATES unique_ids)
    list(LENGTH unique_ids unique_count)
    list(LENGTH paths path_count)
    if(NOT id_count EQUAL 21 OR NOT unique_count EQUAL 21 OR NOT path_count EQUAL 21)
        rf_bootstrap_fail("RF1458" "Linux Stage-1 publication set is incomplete or duplicated")
    endif()

    rf_read_bounded_json("${repository_root}/third_party/artifacts.lock.json" artifact_json)
    string(JSON artifact_count LENGTH "${artifact_json}" artifacts)
    set(selected_count 0)
    math(EXPR artifact_last "${artifact_count} - 1")
    foreach(index RANGE 0 ${artifact_last})
        string(JSON platform GET "${artifact_json}" artifacts ${index} platform)
        if(NOT platform STREQUAL "platform.any" AND NOT platform STREQUAL "platform.linux")
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
            set(path "${repository_root}/out/sync/linux-x86_64/quarantine/artifact-${sha256}")
        endif()
        rf_verify_file_identity("${path}" "${bytes}" "${sha256}" "selected Linux closure artifact ${id}")
    endforeach()
    if(NOT selected_count EQUAL 35)
        rf_bootstrap_fail("RF1459" "Linux host selection does not contain exactly 35 artifacts")
    endif()
    set(${output_ids} "${ids}" PARENT_SCOPE)
    set(${output_paths} "${paths}" PARENT_SCOPE)
endfunction()
