include_guard(GLOBAL)

function(rf_prepare_linux_tools repository_root)
    set(host_root "${repository_root}/out/prepared/linux-x86_64")
    set(tools_root "${host_root}/tools")
    set(tree_root "${repository_root}/out/sync/linux-x86_64/verified-trees")
    file(MAKE_DIRECTORY "${tree_root}" "${tools_root}")

    rf_sync_cache_path("${repository_root}" "tool.llvm.linux_x86_64" llvm_archive llvm_root llvm_format)
    set(llvm_tree "${tree_root}/llvm-df0e1ecf16caf3489a272a5eea4eec9b0d82878f6477fa309504f918a0006384")
    file(REMOVE_RECURSE "${llvm_tree}")
    rf_extract_quarantine("${llvm_archive}" "${llvm_root}" "${llvm_tree}")
    set(llvm_content "${llvm_tree}/${llvm_root}")
    rf_sync_verify_required_tree_files("${repository_root}" "tool.llvm.linux_x86_64" "${llvm_content}")
    execute_process(
        COMMAND "${llvm_content}/bin/clang" --version
        RESULT_VARIABLE clang_result OUTPUT_VARIABLE clang_output ERROR_VARIABLE clang_error TIMEOUT 15
    )
    if(NOT clang_result EQUAL 0 OR NOT clang_output MATCHES
       "clang version 22\\.1\\.8 .*ca7933e47d3a3451d81e72ac174dcb5aa28b59d1")
        rf_bootstrap_fail("RF1521" "prepared Linux LLVM identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${llvm_content}" "${tools_root}/llvm"
        "{\n  \"host\": \"linux-x86_64\",\n  \"tool\": \"tool.llvm\",\n  \"version\": \"22.1.8\",\n  \"archiveSha256\": \"df0e1ecf16caf3489a272a5eea4eec9b0d82878f6477fa309504f918a0006384\"\n}\n"
        "${host_root}"
    )

    rf_sync_cache_path("${repository_root}" "tool.jsonschema_oracle.linux_x86_64"
        oracle_archive oracle_root oracle_format)
    set(oracle_tree "${tree_root}/oracle-96b214be67bf25c6184f1d009a94e082d1eaa83787a8f1878607aebf3185668e")
    file(REMOVE_RECURSE "${oracle_tree}")
    rf_extract_quarantine("${oracle_archive}" "${oracle_root}" "${oracle_tree}")
    set(oracle_content "${oracle_tree}/${oracle_root}")
    rf_sync_verify_required_tree_files(
        "${repository_root}" "tool.jsonschema_oracle.linux_x86_64" "${oracle_content}")
    # The zip carries no POSIX mode, so the extracted oracle is not executable
    # until the tree is prepared. Grant it after its exact identity is proven,
    # never before.
    file(CHMOD "${oracle_content}/bin/jsonschema"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
    execute_process(
        COMMAND "${oracle_content}/bin/jsonschema" version
        RESULT_VARIABLE oracle_result OUTPUT_VARIABLE oracle_output ERROR_VARIABLE oracle_error TIMEOUT 15
    )
    string(STRIP "${oracle_output}" oracle_version)
    if(NOT oracle_result EQUAL 0 OR NOT oracle_version STREQUAL "16.1.0" OR NOT oracle_error STREQUAL "")
        rf_bootstrap_fail("RF1522" "prepared Linux schema-oracle identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${oracle_content}" "${tools_root}/jsonschema"
        "{\n  \"host\": \"linux-x86_64\",\n  \"tool\": \"tool.jsonschema_oracle\",\n  \"version\": \"16.1.0\",\n  \"archiveSha256\": \"96b214be67bf25c6184f1d009a94e082d1eaa83787a8f1878607aebf3185668e\"\n}\n"
        "${host_root}"
    )

    rf_sync_cache_path("${repository_root}" "tool.ninja.linux_x86_64" ninja_archive ninja_root ninja_format)
    set(ninja_tree "${tree_root}/ninja-5749cbc4e668273514150a80e387a957f933c6ed3f5f11e03fb30955e2bbead6")
    file(REMOVE_RECURSE "${ninja_tree}")
    rf_extract_single_file_archive(
        "${ninja_archive}" "ninja" 290928
        "607e668f90dd6cd82e1a42ae572647ad1b1fd43063964295b9547836d8c15d99"
        "${ninja_tree}" ninja_executable
    )
    file(CHMOD "${ninja_executable}"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
    execute_process(
        COMMAND "${ninja_executable}" --version
        RESULT_VARIABLE ninja_result OUTPUT_VARIABLE ninja_output ERROR_VARIABLE ninja_error TIMEOUT 15
    )
    string(STRIP "${ninja_output}" ninja_version)
    if(NOT ninja_result EQUAL 0 OR NOT ninja_version STREQUAL "1.13.2")
        rf_bootstrap_fail("RF1523" "prepared Linux Ninja identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${ninja_tree}" "${tools_root}/ninja"
        "{\n  \"host\": \"linux-x86_64\",\n  \"tool\": \"tool.ninja\",\n  \"version\": \"1.13.2\",\n  \"archiveSha256\": \"5749cbc4e668273514150a80e387a957f933c6ed3f5f11e03fb30955e2bbead6\"\n}\n"
        "${host_root}"
    )
endfunction()

function(rf_prepare_linux_vcpkg repository_root)
    set(tree_root "${repository_root}/out/sync/linux-x86_64/verified-trees")
    rf_sync_cache_path("${repository_root}" "registry.vcpkg_builtin.source"
        registry_archive registry_root registry_format)
    set(registry_tree "${tree_root}/vcpkg-registry-c06bf64239a8fd078efd80bf32cf30cef1c1c057c64cfe61f2d5a3869a3e8544")
    file(REMOVE_RECURSE "${registry_tree}")
    rf_extract_quarantine("${registry_archive}" "${registry_root}" "${registry_tree}")
    set(merged_tree "${tree_root}/vcpkg-merged")
    file(REMOVE_RECURSE "${merged_tree}")
    file(MAKE_DIRECTORY "${merged_tree}")
    file(COPY "${registry_tree}/${registry_root}/" DESTINATION "${merged_tree}")
    rf_sync_cache_path("${repository_root}" "tool.vcpkg.linux_x86_64" vcpkg_binary ignored_root ignored_format)
    file(COPY_FILE "${vcpkg_binary}" "${merged_tree}/vcpkg")
    rf_verify_file_identity(
        "${merged_tree}/vcpkg" 8553216
        "9f68d6f2158c8a1ae4800260fad2972a21a48f2d43c02d40e79049650b5260c9" "prepared vcpkg")
    file(CHMOD "${merged_tree}/vcpkg"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
    execute_process(
        COMMAND "${merged_tree}/vcpkg" version
        WORKING_DIRECTORY "${merged_tree}"
        RESULT_VARIABLE vcpkg_result OUTPUT_VARIABLE vcpkg_output ERROR_VARIABLE vcpkg_error TIMEOUT 15
    )
    if(NOT vcpkg_result EQUAL 0 OR NOT vcpkg_output MATCHES
       "version 2026-07-13-bf04c909169fdbb30821c02c6eb01f1cd1295d05")
        rf_bootstrap_fail("RF1524" "prepared Linux vcpkg identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${merged_tree}" "${repository_root}/out/prepared/linux-x86_64/vcpkg"
        "{\n  \"host\": \"linux-x86_64\",\n  \"tool\": \"tool.vcpkg\",\n  \"version\": \"2026.7.13\",\n  \"binarySha256\": \"9f68d6f2158c8a1ae4800260fad2972a21a48f2d43c02d40e79049650b5260c9\",\n  \"registryCommit\": \"8e8dfb4ba483886936ded5ca201b500b8d8b0096\"\n}\n"
        "${repository_root}/out/prepared/linux-x86_64"
    )
endfunction()
