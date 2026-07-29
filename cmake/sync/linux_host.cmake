include_guard(GLOBAL)

# Probes the exact TASK-0001 locked Linux host tuple `host.ubuntu_24_04_x86_64`.
#
# The tuple has two separate authorities and the probe keeps them separate.
# Package identity comes from the Canonical-signed `noble` Packages index
# that Stage 0 already published, so a locked identity is proven by a signature
# chain rather than by the machine describing itself. Installation state comes
# from the host package database, which can only answer which of those exact
# versions is present. Presence on PATH never admits a component.

include("${CMAKE_CURRENT_LIST_DIR}/../bootstrap/verifier.cmake")

set(RF_LINUX_HOST_ID "host.ubuntu_24_04_x86_64")
# ADR-0083 admits a second host class whose operating-system identity is its
# image digest. On this lane the class changes what the tuple is called and
# nothing about what is proven: an Ubuntu container reports the same
# distribution, release, and codename as the workstation, so the existing
# identity probe stays exactly as it is and still means what it says.
set(RF_LINUX_CONTAINER_HOST_ID "host.container_ubuntu_24_04_x86_64")
set(RF_LINUX_CONTAINER_HOST_MARKER "/rf/host-identity.json")
set(RF_LINUX_HOST_DISTRIBUTION "Ubuntu")
set(RF_LINUX_HOST_RELEASE "24.04")
set(RF_LINUX_HOST_CODENAME "noble")
set(RF_LINUX_HOST_GLIBC_VERSION "2.39-0ubuntu8")

# Package, version, Filename, Size, SHA256 exactly as the locked signed index
# publishes them. The first ten entries follow the Task packet table order.
#
# Entries eleven through fourteen are the host shared libraries the locked LLVM
# primary loads by `DT_NEEDED`. They were previously implicit, which is what let
# the toolchain reach a host whose `libxml2` SONAME had moved past the one
# `ld.lld` requires. A dependency the toolchain cannot start without is part of
# the tuple, so it is pinned by the same signed-index evidence as everything
# else.
#
# The last three carry `pkg-config`, which the OpenSSL port's Autotools
# configuration invokes and which vcpkg does not acquire on Linux. `pkgconf`
# supplies the `pkg-config` name itself; the Ubuntu `pkg-config` package is only
# a transitional shim over it and is deliberately not locked.
set(RF_LINUX_HOST_PACKAGES
    "libc6|2.39-0ubuntu8|pool/main/g/glibc/libc6_2.39-0ubuntu8_amd64.deb|3264806|af36c7ac770770fe3d3c10e85d6bc538e76e57570ba7db7d397fb9f654783ef3"
    "libc-bin|2.39-0ubuntu8|pool/main/g/glibc/libc-bin_2.39-0ubuntu8_amd64.deb|681940|4ff873a8ae9622f0bc4e4be8cb1e5b3e94ff53a93a18af10e54f6e55cd7f92d0"
    "libc-dev-bin|2.39-0ubuntu8|pool/main/g/glibc/libc-dev-bin_2.39-0ubuntu8_amd64.deb|20406|e1d2c6e9e6a4fa06a48703f57e1fad6dd643625eb0a4dd700c156d3a31e7689f"
    "libc6-dev|2.39-0ubuntu8|pool/main/g/glibc/libc6-dev_2.39-0ubuntu8_amd64.deb|2123840|1f03b79223d9cf1a6ed3a648f6942619dcb97b2884dba8fd12e262b6771e247a"
    "linux-libc-dev|6.8.0-31.31|pool/main/l/linux/linux-libc-dev_6.8.0-31.31_amd64.deb|1597672|21c631ba4da3d38d92a133e28a8a14278e1e00174ed135a20661d1e532e05ca5"
    "libcrypt-dev|1:4.4.36-4build1|pool/main/libx/libxcrypt/libcrypt-dev_4.4.36-4build1_amd64.deb|111780|2edff420ef80b4a3f3751e65c33423ef30e563122a58b759e4854ea8d84ba1b1"
    "rpcsvc-proto|1.4.2-0ubuntu7|pool/main/r/rpcsvc-proto/rpcsvc-proto_1.4.2-0ubuntu7_amd64.deb|67446|7eb710fe148d224c159ddec1ceb0ba53ead52a80a6793dcdae1474acf20d8f71"
    "make|4.3-4.1build2|pool/main/m/make-dfsg/make_4.3-4.1build2_amd64.deb|179752|1fe6a815b56c7b6e9ce4086a363f09444bbd0a0d30e230c453d0b78e44b57a99"
    "perl|5.38.2-3.2build2|pool/main/p/perl/perl_5.38.2-3.2build2_amd64.deb|231370|a59f3d152ed767cf3be0924890e64d1f9424ac75f4124672ba6830d2ac587e03"
    "perl-base|5.38.2-3.2build2|pool/main/p/perl/perl-base_5.38.2-3.2build2_amd64.deb|1822564|82a75783b5b63b92d83c3f022e98dba9542e30d3a228b3e381d9c302b14df095"
    "libstdc++6|14-20240412-0ubuntu1|pool/main/g/gcc-14/libstdc++6_14-20240412-0ubuntu1_amd64.deb|795158|4863e880d6ee538e4734c430c5579c1ac933b88a42c25bc9980d0f148c54b21e"
    "libgcc-s1|14-20240412-0ubuntu1|pool/main/g/gcc-14/libgcc-s1_14-20240412-0ubuntu1_amd64.deb|78484|a39efdcaa2245f026dc3254ce14fcff255fc430a17064632b6ba7c5da974a912"
    "zlib1g|1:1.3.dfsg-3.1ubuntu2|pool/main/z/zlib/zlib1g_1.3.dfsg-3.1ubuntu2_amd64.deb|62784|0b93d16d7498f092fa3070fbbad28cdbc6b3d640f1a7681b96fc37f20d1219f1"
    "libxml2|2.9.14+dfsg-1.3ubuntu3|pool/main/libx/libxml2/libxml2_2.9.14+dfsg-1.3ubuntu3_amd64.deb|762198|8c4efd7abe155df3cf0f9b64d659f2d866215785f8e8c44234fbb341d58cc967"
    "libpkgconf3|1.8.1-2build1|pool/main/p/pkgconf/libpkgconf3_1.8.1-2build1_amd64.deb|30652|fc3a57e8f931ec06cb7c51acc56878f1fec247ff02a7adcab26905c2faeb2792"
    "pkgconf-bin|1.8.1-2build1|pool/main/p/pkgconf/pkgconf-bin_1.8.1-2build1_amd64.deb|20730|7a812f05ee1610154b433e2ad54f6e4163fcbb306b9fb31afe959afb2e5e1545"
    "pkgconf|1.8.1-2build1|pool/main/p/pkgconf/pkgconf_1.8.1-2build1_amd64.deb|16790|834a58031069d97d7cfb8b2f5bfd5effc69cecf7f30cc362071875f1f8dc1828"
)

# Resolves which ADR-0083 host class this probe is running under.
#
# The marker states what the environment is, never what it may be trusted with.
# A hand-built image can carry the same file and still produces
# `diagnostic_untrusted` evidence, because trust comes from an ADR-0082
# attestation over the protected workflow and from nothing else. The digest that
# makes a container an identity is enforced by whoever starts it, which is the
# only place it can be known, so this function must not pretend to check it.
function(rf_resolve_linux_host_class output_class output_host_id)
    if(NOT EXISTS "${RF_LINUX_CONTAINER_HOST_MARKER}")
        set(${output_class} "workstation" PARENT_SCOPE)
        set(${output_host_id} "${RF_LINUX_HOST_ID}" PARENT_SCOPE)
        return()
    endif()
    file(READ "${RF_LINUX_CONTAINER_HOST_MARKER}" marker_text LIMIT 4096)
    string(JSON marker_class ERROR_VARIABLE class_error GET "${marker_text}" hostClass)
    string(JSON marker_host ERROR_VARIABLE host_error GET "${marker_text}" hostId)
    string(JSON marker_probe ERROR_VARIABLE probe_error GET "${marker_text}" probeHostId)
    if(class_error OR host_error OR probe_error)
        rf_bootstrap_fail("RF1558" "container host identity marker is unreadable")
    endif()
    if(NOT marker_class STREQUAL "container" OR
       NOT marker_host STREQUAL RF_LINUX_CONTAINER_HOST_ID OR
       NOT marker_probe STREQUAL "linux-x86_64")
        rf_bootstrap_fail("RF1559" "container host identity marker names a different host")
    endif()
    set(${output_class} "container" PARENT_SCOPE)
    set(${output_host_id} "${RF_LINUX_CONTAINER_HOST_ID}" PARENT_SCOPE)
endfunction()

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
    rf_sync_cache_path("${repository_root}" "host.ubuntu.noble_packages"
        packages_archive ignored_root ignored_format)
    rf_read_debian_packages_index(
        "${repository_root}/out/prepared/linux-x86_64/tools/seven_zip/7zz"
        "${packages_archive}"
        "${repository_root}/out/sync/linux-x86_64/host-probe"
        packages_text)

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
    if(NOT measured_count EQUAL 17)
        rf_bootstrap_fail("RF1555" "locked Ubuntu package closure is not exactly seventeen packages")
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
    rf_resolve_linux_host_class(host_class host_id)
    rf_probe_linux_os_identity()
    rf_probe_linux_glibc()
    rf_probe_linux_package_closure("${repository_root}")

    set(report_root "${repository_root}/out/reports/task-0001/linux-x86_64")
    file(MAKE_DIRECTORY "${report_root}")
    file(WRITE "${report_root}/host-tuple.json.tmp"
        "{\n"
        "  \"host\": \"${host_id}\",\n"
        "  \"hostClass\": \"${host_class}\",\n"
        "  \"distribution\": \"${RF_LINUX_HOST_DISTRIBUTION}\",\n"
        "  \"release\": \"${RF_LINUX_HOST_RELEASE}\",\n"
        "  \"codename\": \"${RF_LINUX_HOST_CODENAME}\",\n"
        "  \"glibc\": \"${RF_LINUX_HOST_GLIBC_VERSION}\",\n"
        "  \"lockedPackages\": 17,\n"
        "  \"packageAuthority\": \"host.ubuntu.noble_packages\",\n"
        "  \"state\": \"probed\"\n"
        "}\n")
    file(RENAME "${report_root}/host-tuple.json.tmp" "${report_root}/host-tuple.json")
endfunction()
