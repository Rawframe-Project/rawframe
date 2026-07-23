include_guard(GLOBAL)

function(rf_write_filesystem_registry_version registry_root package version port_version)
    string(SUBSTRING "${package}" 0 1 prefix)
    file(MAKE_DIRECTORY "${registry_root}/versions/${prefix}-")
    file(WRITE "${registry_root}/versions/${prefix}-/${package}.json"
        "{\n  \"versions\": [\n    {\n      \"path\": \"$/ports/${package}/${version}\",\n"
        "      \"version\": \"${version}\",\n      \"port-version\": ${port_version}\n"
        "    }\n  ]\n}\n")
endfunction()

function(rf_copy_registry_port source_root package version registry_root)
    set(source "${source_root}/ports/${package}")
    if(NOT IS_DIRECTORY "${source}" OR NOT EXISTS "${source}/vcpkg.json" OR
       NOT EXISTS "${source}/portfile.cmake")
        rf_bootstrap_fail("RF1483" "verified registry lacks required port ${package}")
    endif()
    file(MAKE_DIRECTORY "${registry_root}/ports/${package}/${version}")
    file(COPY "${source}/" DESTINATION "${registry_root}/ports/${package}/${version}")
endfunction()

function(rf_patch_windows_registry_port registry_root package version)
    set(port_root "${registry_root}/ports/${package}/${version}")
    if(package STREQUAL "gtest")
        set(portfile "${port_root}/portfile.cmake")
        file(READ "${portfile}" content)
        set(old [=[vcpkg_fixup_pkgconfig()
if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "release")
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/lib/pkgconfig/gmock_main.pc" "libdir=\${prefix}/lib" "libdir=\${prefix}/lib/manual-link")
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/lib/pkgconfig/gtest_main.pc" "libdir=\${prefix}/lib" "libdir=\${prefix}/lib/manual-link")
endif()
if(NOT DEFINED VCPKG_BUILD_TYPE OR VCPKG_BUILD_TYPE STREQUAL "debug")
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig/gmock_main.pc" "libdir=\${prefix}/lib" "libdir=\${prefix}/lib/manual-link")
    vcpkg_replace_string("${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig/gtest_main.pc" "libdir=\${prefix}/lib" "libdir=\${prefix}/lib/manual-link")
endif()]=])
        set(new [=[file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/lib/pkgconfig"
    "${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig")]=])
        string(FIND "${content}" "${old}" patch_index)
        if(patch_index EQUAL -1)
            rf_bootstrap_fail("RF1487" "gtest pkg-config suppression patch no longer applies")
        endif()
        string(REPLACE "${old}" "${new}" content "${content}")
        file(WRITE "${portfile}" "${content}")
    elseif(package STREQUAL "simdjson")
        set(portfile "${port_root}/portfile.cmake")
        file(READ "${portfile}" content)
        string(FIND "${content}" "vcpkg_fixup_pkgconfig()" patch_index)
        if(patch_index EQUAL -1)
            rf_bootstrap_fail("RF1488" "simdjson pkg-config suppression patch no longer applies")
        endif()
        set(replacement [=[file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/lib/pkgconfig"
    "${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig")]=])
        string(REPLACE "vcpkg_fixup_pkgconfig()" "${replacement}" content "${content}")
        file(WRITE "${portfile}" "${content}")
    endif()
endfunction()

function(rf_prepare_windows_dependency_authority repository_root)
    set(host "windows-x86_64")
    set(prepared_root "${repository_root}/out/prepared/${host}")
    set(stage_root "${repository_root}/out/sync/${host}/dependency-authority")
    set(registry_stage "${stage_root}/registry")
    set(manifest_stage "${stage_root}/manifest")
    file(REMOVE_RECURSE "${stage_root}")
    file(MAKE_DIRECTORY "${registry_stage}" "${manifest_stage}")

    set(vcpkg_root "${prepared_root}/vcpkg")
    foreach(spec IN ITEMS
            "simdjson|4.6.4|0"
            "gtest|1.17.0|2"
            "vcpkg-cmake|2024-04-23|0"
            "vcpkg-cmake-config|2024-05-23|0"
            "vcpkg-cmake-get-vars|2025-05-29|0")
        string(REPLACE "|" ";" fields "${spec}")
        list(GET fields 0 package)
        list(GET fields 1 version)
        list(GET fields 2 port_version)
        rf_copy_registry_port("${vcpkg_root}" "${package}" "${version}" "${registry_stage}")
        rf_patch_windows_registry_port("${registry_stage}" "${package}" "${version}")
        rf_write_filesystem_registry_version(
            "${registry_stage}" "${package}" "${version}" "${port_version}")
    endforeach()

    set(openssl_source
        "${repository_root}/third_party/vcpkg/registries/rawframe/ports/openssl/3.5.7")
    if(NOT IS_DIRECTORY "${openssl_source}" OR NOT EXISTS "${openssl_source}/vcpkg.json" OR
       NOT EXISTS "${openssl_source}/portfile.cmake")
        rf_bootstrap_fail("RF1484" "Rawframe OpenSSL 3.5.7 registry port is incomplete")
    endif()
    file(MAKE_DIRECTORY "${registry_stage}/ports/openssl/3.5.7")
    file(COPY "${openssl_source}/" DESTINATION "${registry_stage}/ports/openssl/3.5.7")
    set(openssl_portfile "${registry_stage}/ports/openssl/3.5.7/portfile.cmake")
    file(READ "${openssl_portfile}" openssl_content)
    set(openssl_pc_include
        [=[    include("${CMAKE_CURRENT_LIST_DIR}/install-pc-files.cmake")]=])
    string(FIND "${openssl_content}" "${openssl_pc_include}" openssl_patch_index)
    if(openssl_patch_index EQUAL -1)
        rf_bootstrap_fail("RF1489" "OpenSSL pkg-config suppression patch no longer applies")
    endif()
    string(REPLACE "${openssl_pc_include}" "" openssl_content "${openssl_content}")
    file(WRITE "${openssl_portfile}" "${openssl_content}")
    set(openssl_windows_portfile
        "${registry_stage}/ports/openssl/3.5.7/windows/portfile.cmake")
    file(READ "${openssl_windows_portfile}" openssl_windows_content)
    string(FIND "${openssl_windows_content}" "    PREFER_JOM\n" jom_patch_index)
    if(jom_patch_index EQUAL -1)
        rf_bootstrap_fail("RF1490" "OpenSSL nmake-only patch no longer applies")
    endif()
    string(REPLACE "    PREFER_JOM\n" "" openssl_windows_content "${openssl_windows_content}")
    file(WRITE "${openssl_windows_portfile}" "${openssl_windows_content}")
    rf_write_filesystem_registry_version("${registry_stage}" "openssl" "3.5.7" "0")

    file(WRITE "${registry_stage}/versions/baseline.json"
        "{\n  \"rawframe_task_0001\": {\n"
        "    \"gtest\": { \"baseline\": \"1.17.0\", \"port-version\": 2 },\n"
        "    \"openssl\": { \"baseline\": \"3.5.7\", \"port-version\": 0 },\n"
        "    \"simdjson\": { \"baseline\": \"4.6.4\", \"port-version\": 0 },\n"
        "    \"vcpkg-cmake\": { \"baseline\": \"2024-04-23\", \"port-version\": 0 },\n"
        "    \"vcpkg-cmake-config\": { \"baseline\": \"2024-05-23\", \"port-version\": 0 },\n"
        "    \"vcpkg-cmake-get-vars\": { \"baseline\": \"2025-05-29\", \"port-version\": 0 }\n"
        "  }\n}\n")

    set(registry_destination "${prepared_root}/registry")
    rf_publish_prepared_tree(
        "${registry_stage}" "${registry_destination}"
        "{\n  \"host\": \"${host}\",\n  \"kind\": \"filesystem-registry\",\n  \"baseline\": \"rawframe_task_0001\",\n  \"packages\": 6\n}\n"
        "${prepared_root}")

    file(COPY_FILE "${repository_root}/third_party/vcpkg/vcpkg.json"
        "${manifest_stage}/vcpkg.json")
    file(TO_CMAKE_PATH "${registry_destination}" registry_json_path)
    file(WRITE "${manifest_stage}/vcpkg-configuration.json"
        "{\n  \"default-registry\": {\n    \"kind\": \"filesystem\",\n"
        "    \"path\": \"${registry_json_path}\",\n"
        "    \"baseline\": \"rawframe_task_0001\"\n  },\n"
        "  \"overlay-triplets\": [\"${repository_root}/third_party/vcpkg/triplets\"]\n}\n")
    rf_publish_prepared_tree(
        "${manifest_stage}" "${prepared_root}/dependency-manifest"
        "{\n  \"host\": \"${host}\",\n  \"kind\": \"vcpkg-manifest\",\n  \"registryBaseline\": \"rawframe_task_0001\"\n}\n"
        "${prepared_root}")
endfunction()

function(rf_seed_windows_vcpkg_downloads repository_root)
    set(downloads "${repository_root}/out/cache/vcpkg-downloads")
    file(MAKE_DIRECTORY "${downloads}")
    foreach(spec IN ITEMS
            "library.simdjson.source|simdjson-simdjson-v4.6.4.tar.gz|003b96daab30ccaefdac60a9676cf623af5a8662016f988fc0ecaa2f36d8b48ba97f2431e6498dd16fc2b1d841798b2d06dabb0b7487efd4520c0de260e49056"
            "test.googletest.source|google-googletest-v1.17.0.tar.gz|0f57e9ef06925e5b7722df1eb92ef5850e8dce79220ea16a8aaff586a71c0b01460ef1713649ee24ffedb2e6ad5a51e9198c5a5ae1b2789e43feb1f494e7d45c"
            "library.openssl.source|openssl-3.5.7.tar.gz|de5351d2d532e1a3908a738f7d8aae448d32bc60bdb24808c556a24bc37a3f53daedf12b5d432eeb8c235e16939d842f908332ede8a447ca103ad1c493c820d7"
            "tool.archive_extractor.windows_x86_64|7z2602-x64.7z.exe|85389eaef377aa9fef3155d2e3375c1fff77fc10e39d9312cab229f202f3aff78f6e807460cf6b04bc2a32f72f7853afbf475cf0dce6232a40c0a6f8ddcbe4da"
            "tool.ninja.windows_x86_64|ninja-win-1.13.2.zip|55d3d891e8fc6c8ad7f92e172125319896761e57c5125944613d9bbfa5b9374387e9fc1468ad5bcb31464f43fb1c455ea251343942595f42955dc67090aa12ee"
            "tool.powershell.windows_x86_64|PowerShell-7.6.2-win-x64.zip|7aa272c9814e95b5b29c4bd263d14a8650278ebb2544b26d78583d726582aa4b726185a7c918b67f8b6288a35fe928db97ed91251bd9c469105b0421913be4f9")
        string(REPLACE "|" ";" fields "${spec}")
        list(GET fields 0 artifact_id)
        list(GET fields 1 filename)
        list(GET fields 2 expected_sha512)
        rf_sync_cache_path("${repository_root}" "${artifact_id}" source ignored_root ignored_format)
        file(SHA512 "${source}" actual_sha512)
        if(NOT actual_sha512 STREQUAL expected_sha512)
            rf_bootstrap_fail("RF1485" "vcpkg SHA-512 authority mismatch for ${artifact_id}")
        endif()
        file(COPY_FILE "${source}" "${downloads}/${filename}" ONLY_IF_DIFFERENT)
    endforeach()
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
        ninja_archive ignored_root ignored_format)
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
