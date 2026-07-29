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

function(rf_sync_verify_windows_unsigned repository_root transport output_ids output_paths)
    set(ids
        tool.nasm.windows_x86_64
        tool.ninja.windows_x86_64
        tool.perl.windows_x86_64
        tool.powershell.windows_x86_64
    )
    set(paths "")
    foreach(id IN LISTS ids)
        rf_sync_acquire_artifact("${repository_root}" "windows-x86_64" "${transport}" "${id}" artifact)
        list(APPEND paths "${artifact_path}")
        if(id STREQUAL "tool.nasm.windows_x86_64")
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
    rf_sync_verify_openssl_source("${repository_root}" "windows-x86_64" "${transport}" openssl_ids openssl_paths)
    rf_sync_verify_schema_oracle("${repository_root}" "windows-x86_64" "${transport}" oracle_ids oracle_paths)
    rf_sync_verify_llvm_closure("${repository_root}" "windows-x86_64" "${transport}" llvm_ids llvm_paths)
    rf_validate_archive_listing(
        "${repository_root}/out/sync/windows-x86_64/quarantine/artifact-d96c2cc1736f4eb7fa43cb9bbdf56d93551a9ae0a9aadb9c99c3c3b2b712a234"
        "clang+llvm-22.1.8-x86_64-pc-windows-msvc"
    )
    rf_sync_verify_portable_sources("${repository_root}" "windows-x86_64" "${transport}" source_ids source_paths)
    rf_sync_verify_windows_unsigned("${repository_root}" "${transport}" unsigned_ids unsigned_paths)
    rf_sync_verify_license_closure("${repository_root}")

    set(ids "${vcpkg_ids};${openssl_ids};${oracle_ids};${llvm_ids};${source_ids};${unsigned_ids}")
    set(paths "${vcpkg_paths};${openssl_paths};${oracle_paths};${llvm_paths};${source_paths};${unsigned_paths}")
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

