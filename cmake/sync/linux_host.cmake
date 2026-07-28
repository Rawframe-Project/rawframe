include_guard(GLOBAL)

# Probes the exact TASK-0001 locked Linux host tuple `host.ubuntu_26_04_x86_64`.
#
# The tuple has two separate authorities and the probe keeps them separate.
# Package identity comes from the Canonical-signed `resolute` Packages index
# that Stage 0 already published, so a locked identity is proven by a signature
# chain rather than by the machine describing itself. Installation state comes
# from the host package database, which can only answer which of those exact
# versions is present. Presence on PATH never admits a component.

include("${CMAKE_CURRENT_LIST_DIR}/../bootstrap/verifier.cmake")

set(RF_LINUX_HOST_ID "host.ubuntu_26_04_x86_64")
set(RF_LINUX_HOST_DISTRIBUTION "Ubuntu")
set(RF_LINUX_HOST_RELEASE "26.04")
set(RF_LINUX_HOST_CODENAME "resolute")
set(RF_LINUX_HOST_GLIBC_VERSION "2.43-2ubuntu2")

# Package, version, Filename, Size, SHA256 exactly as the locked signed index
# publishes them. Order follows the Task packet table.
set(RF_LINUX_HOST_PACKAGES
    "libc6|2.43-2ubuntu2|pool/main/g/glibc/libc6_2.43-2ubuntu2_amd64.deb|2103270|c13775dc0c984403f3fcad229d14507a9f387763bd07ace1e5f93897ee6b8434"
    "libc-bin|2.43-2ubuntu2|pool/main/g/glibc/libc-bin_2.43-2ubuntu2_amd64.deb|700930|c34230e6892fa95e498e51640f7131946120b83eb672f586e341fa53bf504359"
    "libc-dev-bin|2.43-2ubuntu2|pool/main/g/glibc/libc-dev-bin_2.43-2ubuntu2_amd64.deb|23338|85ffc97dcc6c63c80693b07a984128b9e267992482f12e1c0dd87c65f014c769"
    "libc6-dev|2.43-2ubuntu2|pool/main/g/glibc/libc6-dev_2.43-2ubuntu2_amd64.deb|2295266|6c8def1cafec89468fef8bd0d7a4eb66192a7850bf17c9decf7bca8fcf3dd5fa"
    "linux-libc-dev|7.0.0-14.14|pool/main/l/linux/linux-libc-dev_7.0.0-14.14_amd64.deb|1548426|14bf36d574df2cacf2e50fa8c1f28b4b6b574b63e9561924cc942e4c9186e57e"
    "libcrypt-dev|1:4.5.1-1|pool/main/libx/libxcrypt/libcrypt-dev_4.5.1-1_amd64.deb|121788|a5d86db4dde3de557a419aa3199e916de30b356717c4c1e8974270fda615c051"
    "rpcsvc-proto|1.4.3-1build1|pool/main/r/rpcsvc-proto/rpcsvc-proto_1.4.3-1build1_amd64.deb|68294|d7102b9d3fd35fd7a66d94ba0765a9c8e87b2b80e3633ef4af401dd0c952bafd"
    "make|4.4.1-3|pool/main/m/make-dfsg/make_4.4.1-3_amd64.deb|196620|a86f39d57a32b7c919c0ad721fc2f17ab533a42fda348c8d81a4eea1577a014f"
    "perl|5.40.1-7build1|pool/main/p/perl/perl_5.40.1-7build1_amd64.deb|262182|b1def6b47f4f45852e4f79127fad9b947e2b9c1d5e2282e986b8bdb0ddd51b24"
    "perl-base|5.40.1-7build1|pool/main/p/perl/perl-base_5.40.1-7build1_amd64.deb|1848640|3f8edc884ebb8c55120cb0535fb4e1029651d97fd380936ec5211bb4c926d809"
)

function(rf_probe_linux_os_identity)
    set(release_file "/etc/os-release")
    if(NOT EXISTS "${release_file}")
        rf_bootstrap_fail("RF1525" "host release identity file is missing")
    endif()
    file(READ "${release_file}" release_text LIMIT 8192)
    string(REPLACE "\r" "" release_text "${release_text}")
    foreach(expected IN ITEMS
            "NAME=\"${RF_LINUX_HOST_DISTRIBUTION}\""
            "VERSION_ID=\"${RF_LINUX_HOST_RELEASE}\""
            "VERSION_CODENAME=${RF_LINUX_HOST_CODENAME}")
        string(FIND "\n${release_text}" "\n${expected}\n" field_offset)
        if(field_offset EQUAL -1)
            rf_bootstrap_fail("RF1526" "host release identity differs from the locked tuple")
        endif()
    endforeach()
    cmake_host_system_information(RESULT processor QUERY OS_PLATFORM)
    if(NOT processor STREQUAL "x86_64")
        rf_bootstrap_fail("RF1527" "host architecture differs from the locked tuple")
    endif()
endfunction()

# Reads the exact installed version of one package. `dpkg-query` is admitted on
# the same basis as the Stage-0 transport: a named non-interpreting host utility
# invoked by absolute path, producing a value that is compared, never trusted.
function(rf_query_installed_package package output_version)
    execute_process(
        COMMAND "/usr/bin/dpkg-query" --showformat=\${Version} --show "${package}"
        RESULT_VARIABLE query_result OUTPUT_VARIABLE query_output ERROR_VARIABLE query_error TIMEOUT 30
    )
    string(LENGTH "${query_output}${query_error}" query_bytes)
    if(NOT query_result EQUAL 0 OR query_bytes GREATER 4096)
        rf_bootstrap_fail("RF1528" "locked host package ${package} is not installed")
    endif()
    string(STRIP "${query_output}" version)
    set(${output_version} "${version}" PARENT_SCOPE)
endfunction()

function(rf_probe_linux_package_closure repository_root)
    rf_sync_cache_path("${repository_root}" "host.ubuntu.resolute_packages"
        packages_archive ignored_root ignored_format)
    # A Debian package index is a bare deflate stream rather than an archive
    # container, so it is decompressed by the prepared extractor Stage 0
    # verified, not by the CMake archive reader.
    set(extractor "${repository_root}/out/prepared/linux-x86_64/tools/seven_zip/7zz")
    if(NOT EXISTS "${extractor}")
        rf_bootstrap_fail("RF1529" "prepared archive extractor is missing")
    endif()
    set(probe_root "${repository_root}/out/sync/linux-x86_64/host-probe")
    set(decompressed "${probe_root}/Packages")
    file(MAKE_DIRECTORY "${probe_root}")
    file(REMOVE "${decompressed}")
    execute_process(
        COMMAND "${extractor}" x -so "${packages_archive}"
        RESULT_VARIABLE extract_result OUTPUT_FILE "${decompressed}" ERROR_VARIABLE extract_error TIMEOUT 60
    )
    if(NOT extract_result EQUAL 0 OR NOT EXISTS "${decompressed}")
        rf_bootstrap_fail("RF1529" "signed Packages index could not be decompressed")
    endif()
    file(SIZE "${decompressed}" packages_bytes)
    if(packages_bytes GREATER 67108864)
        rf_bootstrap_fail("RF1529" "signed Packages index exceeds 64 MiB")
    endif()
    file(READ "${decompressed}" packages_text LIMIT 67108865)

    set(measured "")
    foreach(entry IN LISTS RF_LINUX_HOST_PACKAGES)
        string(REPLACE "|" ";" fields "${entry}")
        list(GET fields 0 package)
        list(GET fields 1 version)
        list(GET fields 2 filename)
        list(GET fields 3 bytes)
        list(GET fields 4 sha256)
        rf_require_debian_package_record(
            "${packages_text}" "${package}" "${version}" "${filename}" "${bytes}" "${sha256}")
        rf_query_installed_package("${package}" installed_version)
        if(NOT installed_version STREQUAL version)
            rf_bootstrap_fail("RF1554"
                "installed ${package} differs from the locked snapshot; the host tuple has drifted")
        endif()
        list(APPEND measured "${package}")
    endforeach()
    list(LENGTH measured measured_count)
    if(NOT measured_count EQUAL 10)
        rf_bootstrap_fail("RF1555" "locked Ubuntu package closure is not exactly ten packages")
    endif()
endfunction()

# glibc is the ABI the locked triplet builds against, so its runtime identity is
# proven from the loader itself rather than from the package version alone.
function(rf_probe_linux_glibc)
    execute_process(
        COMMAND "/usr/bin/ldd" --version
        RESULT_VARIABLE ldd_result OUTPUT_VARIABLE ldd_output ERROR_VARIABLE ldd_error TIMEOUT 15
    )
    string(LENGTH "${ldd_output}${ldd_error}" ldd_bytes)
    if(NOT ldd_result EQUAL 0 OR ldd_bytes GREATER 8192)
        rf_bootstrap_fail("RF1556" "host C runtime identity could not be measured")
    endif()
    string(REGEX MATCH "GLIBC ([0-9]+\\.[0-9]+)-([0-9A-Za-z.~+]+)\\)" glibc_match "${ldd_output}")
    if(NOT glibc_match OR NOT "${CMAKE_MATCH_1}-${CMAKE_MATCH_2}" STREQUAL RF_LINUX_HOST_GLIBC_VERSION)
        rf_bootstrap_fail("RF1557" "host glibc differs from the locked tuple")
    endif()
endfunction()

function(rf_probe_linux_host_tuple repository_root)
    rf_probe_linux_os_identity()
    rf_probe_linux_glibc()
    rf_probe_linux_package_closure("${repository_root}")

    set(report_root "${repository_root}/out/reports/task-0001/linux-x86_64")
    file(MAKE_DIRECTORY "${report_root}")
    file(WRITE "${report_root}/host-tuple.json.tmp"
        "{\n"
        "  \"host\": \"${RF_LINUX_HOST_ID}\",\n"
        "  \"distribution\": \"${RF_LINUX_HOST_DISTRIBUTION}\",\n"
        "  \"release\": \"${RF_LINUX_HOST_RELEASE}\",\n"
        "  \"codename\": \"${RF_LINUX_HOST_CODENAME}\",\n"
        "  \"glibc\": \"${RF_LINUX_HOST_GLIBC_VERSION}\",\n"
        "  \"lockedPackages\": 10,\n"
        "  \"packageAuthority\": \"host.ubuntu.resolute_packages\",\n"
        "  \"state\": \"probed\"\n"
        "}\n")
    file(RENAME "${report_root}/host-tuple.json.tmp" "${report_root}/host-tuple.json")
endfunction()
