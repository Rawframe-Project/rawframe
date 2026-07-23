include_guard(GLOBAL)

function(rf_prepare_windows_tools repository_root)
    set(host_root "${repository_root}/out/prepared/windows-x86_64")
    set(tools_root "${host_root}/tools")
    set(tree_root "${repository_root}/out/sync/windows-x86_64/verified-trees")
    file(MAKE_DIRECTORY "${tree_root}" "${tools_root}")

    rf_sync_cache_path("${repository_root}" "tool.llvm.windows_x86_64" llvm_archive llvm_root llvm_format)
    set(llvm_tree "${tree_root}/llvm-d96c2cc1736f4eb7fa43cb9bbdf56d93551a9ae0a9aadb9c99c3c3b2b712a234")
    file(REMOVE_RECURSE "${llvm_tree}")
    rf_extract_quarantine("${llvm_archive}" "${llvm_root}" "${llvm_tree}")
    set(llvm_content "${llvm_tree}/${llvm_root}")
    rf_sync_verify_required_tree_files("${repository_root}" "tool.llvm.windows_x86_64" "${llvm_content}")
    execute_process(
        COMMAND "${llvm_content}/bin/clang-cl.exe" --version
        RESULT_VARIABLE clang_result OUTPUT_VARIABLE clang_output ERROR_VARIABLE clang_error TIMEOUT 15
    )
    if(NOT clang_result EQUAL 0 OR NOT clang_output MATCHES
       "clang version 22\\.1\\.8 .*ca7933e47d3a3451d81e72ac174dcb5aa28b59d1")
        rf_bootstrap_fail("RF1470" "prepared Windows LLVM identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${llvm_content}" "${tools_root}/llvm"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.llvm\",\n  \"version\": \"22.1.8\",\n  \"archiveSha256\": \"d96c2cc1736f4eb7fa43cb9bbdf56d93551a9ae0a9aadb9c99c3c3b2b712a234\"\n}\n"
        "${host_root}"
    )

    rf_sync_cache_path("${repository_root}" "tool.jsonschema_oracle.windows_x86_64"
        oracle_archive oracle_root oracle_format)
    set(oracle_tree "${tree_root}/oracle-986aa0a16f0b0ef103487dd4e65be833c358e07603bf336ad0a598feb69993da")
    file(REMOVE_RECURSE "${oracle_tree}")
    rf_extract_quarantine("${oracle_archive}" "${oracle_root}" "${oracle_tree}")
    set(oracle_content "${oracle_tree}/${oracle_root}")
    rf_sync_verify_required_tree_files(
        "${repository_root}" "tool.jsonschema_oracle.windows_x86_64" "${oracle_content}")
    execute_process(
        COMMAND "${oracle_content}/bin/jsonschema.exe" version
        RESULT_VARIABLE oracle_result OUTPUT_VARIABLE oracle_output ERROR_VARIABLE oracle_error TIMEOUT 15
    )
    string(STRIP "${oracle_output}" oracle_version)
    if(NOT oracle_result EQUAL 0 OR NOT oracle_version STREQUAL "16.1.0" OR NOT oracle_error STREQUAL "")
        rf_bootstrap_fail("RF1471" "prepared Windows schema-oracle identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${oracle_content}" "${tools_root}/jsonschema"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.jsonschema_oracle\",\n  \"version\": \"16.1.0\",\n  \"archiveSha256\": \"986aa0a16f0b0ef103487dd4e65be833c358e07603bf336ad0a598feb69993da\"\n}\n"
        "${host_root}"
    )

    rf_sync_cache_path("${repository_root}" "tool.nasm.windows_x86_64" nasm_archive nasm_root nasm_format)
    set(nasm_tree "${tree_root}/nasm-e0ba5157007abc7b1a65118a96657a961ddf55f7e3f632ee035366dfce039ca4")
    file(REMOVE_RECURSE "${nasm_tree}")
    rf_extract_quarantine("${nasm_archive}" "${nasm_root}" "${nasm_tree}")
    set(nasm_content "${nasm_tree}/${nasm_root}")
    rf_sync_verify_required_tree_files("${repository_root}" "tool.nasm.windows_x86_64" "${nasm_content}")
    execute_process(
        COMMAND "${nasm_content}/nasm.exe" -v
        RESULT_VARIABLE nasm_result OUTPUT_VARIABLE nasm_output ERROR_VARIABLE nasm_error TIMEOUT 15
    )
    if(NOT nasm_result EQUAL 0 OR NOT nasm_output MATCHES "^NASM version 3\\.01 ")
        rf_bootstrap_fail("RF1472" "prepared NASM identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${nasm_content}" "${tools_root}/nasm"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.nasm\",\n  \"version\": \"3.01\",\n  \"archiveSha256\": \"e0ba5157007abc7b1a65118a96657a961ddf55f7e3f632ee035366dfce039ca4\"\n}\n"
        "${host_root}"
    )

    rf_sync_cache_path("${repository_root}" "tool.ninja.windows_x86_64" ninja_archive ninja_root ninja_format)
    set(ninja_tree "${tree_root}/ninja-07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65")
    file(REMOVE_RECURSE "${ninja_tree}")
    rf_extract_single_file_archive(
        "${ninja_archive}" "ninja.exe" 603648
        "e52a7ad9538d9618c67a0bd777964e2eec8a30f68b810a2f6adce1f2daf847b8"
        "${ninja_tree}" ninja_executable
    )
    execute_process(
        COMMAND "${ninja_executable}" --version
        RESULT_VARIABLE ninja_result OUTPUT_VARIABLE ninja_output ERROR_VARIABLE ninja_error TIMEOUT 15
    )
    string(STRIP "${ninja_output}" ninja_version)
    if(NOT ninja_result EQUAL 0 OR NOT ninja_version STREQUAL "1.13.2")
        rf_bootstrap_fail("RF1473" "prepared Ninja identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${ninja_tree}" "${tools_root}/ninja"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.ninja\",\n  \"version\": \"1.13.2\",\n  \"archiveSha256\": \"07fc8261b42b20e71d1720b39068c2e14ffcee6396b76fb7a795fb460b78dc65\"\n}\n"
        "${host_root}"
    )

    rf_sync_cache_path("${repository_root}" "tool.perl.windows_x86_64" perl_archive perl_roots perl_format)
    set(perl_tree "${tree_root}/perl-32d83be90cf04b807cfb9477482bc36302cdee6f5b04cf57e81adecbd8f07898")
    file(REMOVE_RECURSE "${perl_tree}")
    rf_extract_multi_root_quarantine("${perl_archive}" "${perl_roots}" "${perl_tree}")
    rf_sync_verify_required_tree_files("${repository_root}" "tool.perl.windows_x86_64" "${perl_tree}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env --unset=LANG --unset=LC_ALL --unset=LC_CTYPE
            "LC_ALL=C" "${perl_tree}/perl/bin/perl.exe" --version
        RESULT_VARIABLE perl_result OUTPUT_VARIABLE perl_output ERROR_VARIABLE perl_error TIMEOUT 15
    )
    if(NOT perl_result EQUAL 0 OR NOT perl_output MATCHES "version 42, subversion 2 \\(v5\\.42\\.2\\)")
        rf_bootstrap_fail("RF1480" "prepared Strawberry Perl identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${perl_tree}" "${tools_root}/perl"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.perl\",\n  \"version\": \"5.42.2.1\",\n  \"archiveSha256\": \"32d83be90cf04b807cfb9477482bc36302cdee6f5b04cf57e81adecbd8f07898\"\n}\n"
        "${host_root}"
    )

    rf_sync_load_artifact("${repository_root}" "tool.powershell.windows_x86_64" powershell)
    rf_sync_cache_path("${repository_root}" "tool.powershell.windows_x86_64"
        powershell_archive ignored_root ignored_format)
    set(powershell_tree
        "${tree_root}/powershell-32e0dd26752483ba3f0e40e9ae44150643cbff469c13210c93295d158bfd7b26")
    file(REMOVE_RECURSE "${powershell_tree}")
    rf_extract_rootless_quarantine(
        "${powershell_archive}" "${powershell_archive_rootless_entry_count}"
        "${powershell_archive_rootless_top_directories}" "${powershell_archive_rootless_top_files}"
        "${powershell_tree}")
    rf_sync_verify_required_tree_files(
        "${repository_root}" "tool.powershell.windows_x86_64" "${powershell_tree}")
    rf_verify_windows_authenticode(
        "C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe" 543144
        "e7b517a6a2828af2d1fba3da60ae1e322a95141bfae192622725329630caa2b3"
        "${powershell_tree}/pwsh.exe" "AB172913A2960A224809EE8A0C371CD47A079B72"
        "PowerShell 7.6.2 pwsh.exe"
    )
    execute_process(
        COMMAND "${powershell_tree}/pwsh.exe" -NoLogo -NoProfile -Command "$PSVersionTable.PSVersion.ToString()"
        RESULT_VARIABLE powershell_result OUTPUT_VARIABLE powershell_output ERROR_VARIABLE powershell_error TIMEOUT 60
    )
    string(STRIP "${powershell_output}" powershell_version)
    if(NOT powershell_result EQUAL 0 OR NOT powershell_version STREQUAL "7.6.2")
        rf_bootstrap_fail("RF1464" "prepared PowerShell identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${powershell_tree}" "${tools_root}/powershell"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.powershell\",\n  \"version\": \"7.6.2\",\n  \"archiveSha256\": \"32e0dd26752483ba3f0e40e9ae44150643cbff469c13210c93295d158bfd7b26\"\n}\n"
        "${host_root}"
    )
endfunction()

function(rf_prepare_windows_vcpkg repository_root)
    set(tree_root "${repository_root}/out/sync/windows-x86_64/verified-trees")
    rf_sync_cache_path("${repository_root}" "registry.vcpkg_builtin.source"
        registry_archive registry_root registry_format)
    set(registry_tree "${tree_root}/vcpkg-registry-c06bf64239a8fd078efd80bf32cf30cef1c1c057c64cfe61f2d5a3869a3e8544")
    file(REMOVE_RECURSE "${registry_tree}")
    rf_extract_quarantine("${registry_archive}" "${registry_root}" "${registry_tree}")
    set(merged_tree "${tree_root}/vcpkg-merged")
    file(REMOVE_RECURSE "${merged_tree}")
    file(MAKE_DIRECTORY "${merged_tree}")
    file(COPY "${registry_tree}/${registry_root}/" DESTINATION "${merged_tree}")
    rf_sync_cache_path("${repository_root}" "tool.vcpkg.windows_x86_64" vcpkg_binary ignored_root ignored_format)
    file(COPY_FILE "${vcpkg_binary}" "${merged_tree}/vcpkg.exe")
    rf_verify_file_identity(
        "${merged_tree}/vcpkg.exe" 6749536
        "67958c6a13a35130ff8035bef33097ffe3376a6708577a826cfa41fa592db611" "prepared vcpkg.exe")
    execute_process(
        COMMAND "${merged_tree}/vcpkg.exe" version
        WORKING_DIRECTORY "${merged_tree}"
        RESULT_VARIABLE vcpkg_result OUTPUT_VARIABLE vcpkg_output ERROR_VARIABLE vcpkg_error TIMEOUT 15
    )
    if(NOT vcpkg_result EQUAL 0 OR NOT vcpkg_output MATCHES
       "version 2026-07-13-bf04c909169fdbb30821c02c6eb01f1cd1295d05")
        rf_bootstrap_fail("RF1481" "prepared vcpkg identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${merged_tree}" "${repository_root}/out/prepared/windows-x86_64/vcpkg"
        "{\n  \"host\": \"windows-x86_64\",\n  \"tool\": \"tool.vcpkg\",\n  \"version\": \"2026.7.13\",\n  \"binarySha256\": \"67958c6a13a35130ff8035bef33097ffe3376a6708577a826cfa41fa592db611\",\n  \"registryCommit\": \"8e8dfb4ba483886936ded5ca201b500b8d8b0096\"\n}\n"
        "${repository_root}/out/prepared/windows-x86_64"
    )
endfunction()

