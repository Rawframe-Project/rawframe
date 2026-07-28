include_guard(GLOBAL)

# Host-independent half of the prepared dependency authority.
#
# The registry layout, the port set, the baseline, the manifest, and the source
# download seeding are properties of the accepted Task, not of the host running
# the build, so both host lanes resolve them here instead of keeping two copies
# that could drift. Only the OpenSSL patch stack differs per host, and each lane
# supplies its own patch function by name.

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

# The locked host closures carry no pkg-config implementation, and nothing in
# this Task consumes a `.pc` file. Rather than admit pkgconf solely to rewrite
# metadata that is then discarded, each port drops the directory outright. The
# anchors are asserted so an upstream port revision fails loudly instead of
# silently leaving an unusable fixup call behind.
set(RF_PKGCONFIG_REMOVAL [=[file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/lib/pkgconfig"
    "${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig")]=])

function(rf_suppress_registry_port_pkgconfig registry_root package version)
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
        string(FIND "${content}" "${old}" patch_index)
        if(patch_index EQUAL -1)
            rf_bootstrap_fail("RF1487" "gtest pkg-config suppression patch no longer applies")
        endif()
        string(REPLACE "${old}" "${RF_PKGCONFIG_REMOVAL}" content "${content}")
        file(WRITE "${portfile}" "${content}")
    elseif(package STREQUAL "simdjson")
        set(portfile "${port_root}/portfile.cmake")
        file(READ "${portfile}" content)
        string(FIND "${content}" "vcpkg_fixup_pkgconfig()" patch_index)
        if(patch_index EQUAL -1)
            rf_bootstrap_fail("RF1488" "simdjson pkg-config suppression patch no longer applies")
        endif()
        string(REPLACE "vcpkg_fixup_pkgconfig()" "${RF_PKGCONFIG_REMOVAL}" content "${content}")
        file(WRITE "${portfile}" "${content}")
    endif()
endfunction()

function(rf_copy_rawframe_openssl_port repository_root registry_root)
    set(source "${repository_root}/third_party/vcpkg/registries/rawframe/ports/openssl/3.5.7")
    if(NOT IS_DIRECTORY "${source}" OR NOT EXISTS "${source}/vcpkg.json" OR
       NOT EXISTS "${source}/portfile.cmake")
        rf_bootstrap_fail("RF1484" "Rawframe OpenSSL 3.5.7 registry port is incomplete")
    endif()
    file(MAKE_DIRECTORY "${registry_root}/ports/openssl/3.5.7")
    file(COPY "${source}/" DESTINATION "${registry_root}/ports/openssl/3.5.7")
endfunction()

function(rf_write_rawframe_registry_baseline registry_root)
    file(WRITE "${registry_root}/versions/baseline.json"
        "{\n  \"rawframe_task_0001\": {\n"
        "    \"gtest\": { \"baseline\": \"1.17.0\", \"port-version\": 2 },\n"
        "    \"openssl\": { \"baseline\": \"3.5.7\", \"port-version\": 0 },\n"
        "    \"simdjson\": { \"baseline\": \"4.6.4\", \"port-version\": 0 },\n"
        "    \"vcpkg-cmake\": { \"baseline\": \"2024-04-23\", \"port-version\": 0 },\n"
        "    \"vcpkg-cmake-config\": { \"baseline\": \"2024-05-23\", \"port-version\": 0 },\n"
        "    \"vcpkg-cmake-get-vars\": { \"baseline\": \"2025-05-29\", \"port-version\": 0 }\n"
        "  }\n}\n")
endfunction()

# Builds the complete prepared dependency authority for one host: the narrow
# filesystem registry derived from the verified vcpkg snapshot, and the manifest
# root that selects it. `openssl_patch_function` names the host lane's OpenSSL
# patch function, which receives the staged registry root.
function(rf_prepare_dependency_authority repository_root host openssl_patch_function)
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
        rf_suppress_registry_port_pkgconfig("${registry_stage}" "${package}" "${version}")
        rf_write_filesystem_registry_version(
            "${registry_stage}" "${package}" "${version}" "${port_version}")
    endforeach()

    rf_copy_rawframe_openssl_port("${repository_root}" "${registry_stage}")
    cmake_language(CALL "${openssl_patch_function}" "${registry_stage}")
    rf_write_filesystem_registry_version("${registry_stage}" "openssl" "3.5.7" "0")
    rf_write_rawframe_registry_baseline("${registry_stage}")

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

# Copies one already verified CAS object into vcpkg's download cache under the
# exact filename vcpkg expects, after confirming the second, independent SHA-512
# authority vcpkg itself checks. The SHA-256 authority was proven at publication.
function(rf_seed_vcpkg_download repository_root artifact_id filename expected_sha512)
    set(downloads "${repository_root}/out/cache/vcpkg-downloads")
    rf_sync_cache_path("${repository_root}" "${artifact_id}" source ignored_root ignored_format)
    file(SHA512 "${source}" actual_sha512)
    if(NOT actual_sha512 STREQUAL expected_sha512)
        rf_bootstrap_fail("RF1485" "vcpkg SHA-512 authority mismatch for ${artifact_id}")
    endif()
    file(COPY_FILE "${source}" "${downloads}/${filename}" ONLY_IF_DIFFERENT)
endfunction()

# The three dependency sources are `platform.any` artifacts and vcpkg requests
# them under the same filenames on every host.
function(rf_seed_vcpkg_source_downloads repository_root)
    file(MAKE_DIRECTORY "${repository_root}/out/cache/vcpkg-downloads")
    rf_seed_vcpkg_download("${repository_root}" "library.simdjson.source"
        "simdjson-simdjson-v4.6.4.tar.gz"
        "003b96daab30ccaefdac60a9676cf623af5a8662016f988fc0ecaa2f36d8b48ba97f2431e6498dd16fc2b1d841798b2d06dabb0b7487efd4520c0de260e49056")
    rf_seed_vcpkg_download("${repository_root}" "test.googletest.source"
        "google-googletest-v1.17.0.tar.gz"
        "0f57e9ef06925e5b7722df1eb92ef5850e8dce79220ea16a8aaff586a71c0b01460ef1713649ee24ffedb2e6ad5a51e9198c5a5ae1b2789e43feb1f494e7d45c")
    rf_seed_vcpkg_download("${repository_root}" "library.openssl.source"
        "openssl-3.5.7.tar.gz"
        "de5351d2d532e1a3908a738f7d8aae448d32bc60bdb24808c556a24bc37a3f53daedf12b5d432eeb8c235e16939d842f908332ede8a447ca103ad1c493c820d7")
endfunction()
