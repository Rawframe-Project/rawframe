include_guard(GLOBAL)

include("${CMAKE_CURRENT_LIST_DIR}/portable_dependencies.cmake")

# On Windows the OpenSSL port takes the nmake branch, which is the only branch
# that installs generated `.pc` files, and which prefers JOM. The accepted Task
# locks nmake as the build tool and admits no pkg-config implementation, so both
# are removed. The unix branch is untouched here; it is the Linux lane's concern.
function(rf_patch_windows_openssl_port registry_root)
    set(port_root "${registry_root}/ports/openssl/3.5.7")
    set(portfile "${port_root}/portfile.cmake")
    file(READ "${portfile}" content)
    set(pc_include
        [=[    include("${CMAKE_CURRENT_LIST_DIR}/install-pc-files.cmake")]=])
    string(FIND "${content}" "${pc_include}" patch_index)
    if(patch_index EQUAL -1)
        rf_bootstrap_fail("RF1489" "OpenSSL pkg-config suppression patch no longer applies")
    endif()
    string(REPLACE "${pc_include}" "" content "${content}")
    file(WRITE "${portfile}" "${content}")

    set(windows_portfile "${port_root}/windows/portfile.cmake")
    file(READ "${windows_portfile}" windows_content)
    string(FIND "${windows_content}" "    PREFER_JOM\n" jom_patch_index)
    if(jom_patch_index EQUAL -1)
        rf_bootstrap_fail("RF1490" "OpenSSL nmake-only patch no longer applies")
    endif()
    string(REPLACE "    PREFER_JOM\n" "" windows_content "${windows_content}")
    file(WRITE "${windows_portfile}" "${windows_content}")
endfunction()

function(rf_prepare_windows_dependency_authority repository_root)
    rf_prepare_dependency_authority(
        "${repository_root}" "windows-x86_64" rf_patch_windows_openssl_port)
endfunction()

function(rf_seed_windows_vcpkg_downloads repository_root)
    file(MAKE_DIRECTORY "${repository_root}/out/cache/vcpkg-downloads")
    rf_seed_vcpkg_source_downloads("${repository_root}")
    rf_seed_vcpkg_download("${repository_root}" "tool.archive_extractor.windows_x86_64"
        "7z2602-x64.7z.exe"
        "85389eaef377aa9fef3155d2e3375c1fff77fc10e39d9312cab229f202f3aff78f6e807460cf6b04bc2a32f72f7853afbf475cf0dce6232a40c0a6f8ddcbe4da")
    rf_seed_vcpkg_download("${repository_root}" "tool.ninja.windows_x86_64"
        "ninja-win-1.13.2.zip"
        "55d3d891e8fc6c8ad7f92e172125319896761e57c5125944613d9bbfa5b9374387e9fc1468ad5bcb31464f43fb1c455ea251343942595f42955dc67090aa12ee")
    rf_seed_vcpkg_download("${repository_root}" "tool.powershell.windows_x86_64"
        "PowerShell-7.6.2-win-x64.zip"
        "7aa272c9814e95b5b29c4bd263d14a8650278ebb2544b26d78583d726582aa4b726185a7c918b67f8b6288a35fe928db97ed91251bd9c469105b0421913be4f9")
endfunction()

function(rf_seed_windows_vcpkg_tool_trees repository_root)
    set(tools_root "${repository_root}/out/cache/vcpkg-downloads/tools")
    set(stage_root "${repository_root}/out/sync/windows-x86_64/vcpkg-tool-trees")
    file(REMOVE_RECURSE "${stage_root}")
    file(MAKE_DIRECTORY "${tools_root}" "${stage_root}")

    rf_sync_cache_path("${repository_root}" "tool.archive_extractor.windows_x86_64"
        seven_zip_installer ignored_root ignored_format)
    set(seven_zip_stage "${stage_root}/7zip-26.02-windows")
    rf_extract_seven_zip("${seven_zip_installer}" "${seven_zip_stage}" seven_zip_executable)
    rf_load_required_file("${repository_root}" "tool.archive_extractor.windows_x86_64"
        "7z.exe" seven_zip_required)
    rf_verify_file_identity("${seven_zip_executable}" "${seven_zip_required_byteSize}"
        "${seven_zip_required_sha256}" "vcpkg tool-cache 7z.exe")
    rf_publish_prepared_tree(
        "${seven_zip_stage}" "${tools_root}/7zip-26.02-windows"
        "{\n  \"host\": \"windows-x86_64\",\n  \"kind\": \"vcpkg-tool-cache\",\n  \"tool\": \"tool.archive_extractor\",\n  \"version\": \"26.02\",\n  \"installerSha256\": \"6745fa76dc2ea031596d8678f6f6b99c3c1b435b4164a63485adbbc7b8d82ef0\"\n}\n")

    rf_sync_cache_path("${repository_root}" "tool.ninja.windows_x86_64"
        ninja_archive ninja_root ninja_format)
    rf_load_required_file("${repository_root}" "tool.ninja.windows_x86_64" "ninja.exe" ninja_required)
    set(ninja_stage "${stage_root}/ninja-1.13.2-windows")
    rf_extract_single_file_archive(
        "${ninja_archive}" "ninja.exe" "${ninja_required_byteSize}" "${ninja_required_sha256}"
        "${ninja_stage}" ninja_executable)
    rf_publish_prepared_tree(
        "${ninja_stage}" "${tools_root}/ninja-1.13.2-windows"
        "{\n  \"host\": \"windows-x86_64\",\n  \"kind\": \"vcpkg-tool-cache\",\n  \"tool\": \"tool.ninja\",\n  \"version\": \"1.13.2\",\n  \"archiveSha256\": \"07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65\"\n}\n")

    rf_sync_load_artifact("${repository_root}" "tool.powershell.windows_x86_64" powershell)
    rf_sync_cache_path("${repository_root}" "tool.powershell.windows_x86_64"
        powershell_archive ignored_root ignored_format)
    set(powershell_stage "${stage_root}/powershell-core-7.6.2-windows")
    rf_extract_rootless_quarantine(
        "${powershell_archive}" "${powershell_archive_rootless_entry_count}"
        "${powershell_archive_rootless_top_directories}" "${powershell_archive_rootless_top_files}"
        "${powershell_stage}")
    rf_sync_verify_required_tree_files(
        "${repository_root}" "tool.powershell.windows_x86_64" "${powershell_stage}")
    rf_publish_prepared_tree(
        "${powershell_stage}" "${tools_root}/powershell-core-7.6.2-windows"
        "{\n  \"host\": \"windows-x86_64\",\n  \"kind\": \"vcpkg-tool-cache\",\n  \"tool\": \"tool.powershell\",\n  \"version\": \"7.6.2\",\n  \"archiveSha256\": \"32e0dd26752483ba3f0e40e9ae44150643cbff469c13210c93295d158bfd7b26\"\n}\n")
endfunction()
