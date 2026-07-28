include_guard(GLOBAL)

include("${CMAKE_CURRENT_LIST_DIR}/portable_dependencies.cmake")

# On Linux the OpenSSL port takes the unix branch. That branch never includes
# the Windows `install-pc-files.cmake` helper and never mentions JOM, so neither
# Windows patch applies here; the one pkg-config authority on this path is the
# port's own `vcpkg_fixup_pkgconfig()` call, which the locked host closure has no
# implementation for. It is replaced with the same removal the other ports use.
function(rf_patch_linux_openssl_port registry_root)
    set(portfile "${registry_root}/ports/openssl/3.5.7/unix/portfile.cmake")
    file(READ "${portfile}" content)
    string(FIND "${content}" "vcpkg_fixup_pkgconfig()" patch_index)
    if(patch_index EQUAL -1)
        rf_bootstrap_fail("RF1580" "OpenSSL unix pkg-config suppression patch no longer applies")
    endif()
    string(REPLACE "vcpkg_fixup_pkgconfig()" "${RF_PKGCONFIG_REMOVAL}" content "${content}")
    file(WRITE "${portfile}" "${content}")
endfunction()

function(rf_prepare_linux_dependency_authority repository_root)
    rf_prepare_dependency_authority(
        "${repository_root}" "linux-x86_64" rf_patch_linux_openssl_port)
endfunction()

function(rf_seed_linux_vcpkg_downloads repository_root)
    file(MAKE_DIRECTORY "${repository_root}/out/cache/vcpkg-downloads")
    rf_seed_vcpkg_source_downloads("${repository_root}")
    # vcpkg names the Linux Ninja download `ninja-linux-1.13.2.zip` while the
    # upstream release asset is `ninja-linux.zip`; the locked artifact is the same
    # bytes, and its SHA-512 is asserted against the value vcpkg itself expects.
    rf_seed_vcpkg_download("${repository_root}" "tool.ninja.linux_x86_64"
        "ninja-linux-1.13.2.zip"
        "714b900cf10b7ecb1b641c91f4ef696250c64984e5955a8088e4a538d6e8077f43e55f6da47efcedbe316c68d51a9e98feff51734eb0eac1b17aa85af5698753")
endfunction()

# vcpkg resolves its internal tools before consulting PATH, so the one tool it
# would otherwise acquire is published from the already verified artifact. The
# locked host closure supplies `perl`, `make`, and the archive readers the unix
# OpenSSL recipe needs, so no further tool root is seeded.
function(rf_seed_linux_vcpkg_tool_trees repository_root)
    set(tools_root "${repository_root}/out/cache/vcpkg-downloads/tools")
    set(stage_root "${repository_root}/out/sync/linux-x86_64/vcpkg-tool-trees")
    file(REMOVE_RECURSE "${stage_root}")
    file(MAKE_DIRECTORY "${tools_root}" "${stage_root}")

    rf_sync_cache_path("${repository_root}" "tool.ninja.linux_x86_64"
        ninja_archive ninja_root ninja_format)
    set(ninja_stage "${stage_root}/ninja-1.13.2-linux")
    rf_extract_single_file_archive(
        "${ninja_archive}" "ninja" 290928
        "607e668f90dd6cd82e1a42ae572647ad1b1fd43063964295b9547836d8c15d99"
        "${ninja_stage}" ninja_executable)
    # The zip carries no POSIX mode. The execute bit is granted only after the
    # exact identity above is proven, never before.
    file(CHMOD "${ninja_executable}"
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)
    execute_process(
        COMMAND "${ninja_executable}" --version
        RESULT_VARIABLE ninja_result OUTPUT_VARIABLE ninja_output ERROR_VARIABLE ninja_error TIMEOUT 15
    )
    string(STRIP "${ninja_output}" ninja_version)
    if(NOT ninja_result EQUAL 0 OR NOT ninja_version STREQUAL "1.13.2")
        rf_bootstrap_fail("RF1581" "vcpkg tool-cache Ninja identity mismatch")
    endif()
    rf_publish_prepared_tree(
        "${ninja_stage}" "${tools_root}/ninja-1.13.2-linux"
        "{\n  \"host\": \"linux-x86_64\",\n  \"kind\": \"vcpkg-tool-cache\",\n  \"tool\": \"tool.ninja\",\n  \"version\": \"1.13.2\",\n  \"archiveSha256\": \"5749cbc4e668273514150a80e387a957f933c6ed3f5f11e03fb30955e2bbead6\"\n}\n")
endfunction()
