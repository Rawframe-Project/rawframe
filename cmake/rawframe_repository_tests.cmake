include_guard(GLOBAL)

# Registers the repository conformance fixtures with CTest so one committed
# test preset runs the unit, schema, repository, archive, signature, license,
# offline, and hostile-input coverage together. Every command uses the exact
# configuring CMake binary and only committed fixtures, locked cache objects,
# and prepared trees; nothing here may acquire bytes from the network.

function(rawframe_register_repository_tests)
    set(fixture_scripts "${CMAKE_SOURCE_DIR}/cmake/sync/tests")
    set(fixture_archives "${CMAKE_SOURCE_DIR}/tools/rf_evidence/tests/fixtures/archives")
    set(scratch_root "${CMAKE_BINARY_DIR}/fixture_scratch")
    set(repository_root_argument "-DRF_REPOSITORY_ROOT=${CMAKE_SOURCE_DIR}")
    set(denied_transport "denied-no-transport")

    file(READ "${CMAKE_SOURCE_DIR}/third_party/artifacts.lock.json" artifacts_lock LIMIT 1048576)
    string(JSON artifact_count LENGTH "${artifacts_lock}" artifacts)
    math(EXPR artifact_last "${artifact_count} - 1")
    foreach(index RANGE 0 ${artifact_last})
        string(JSON artifact_id GET "${artifacts_lock}" artifacts ${index} id)
        string(JSON artifact_sha GET "${artifacts_lock}" artifacts ${index} sha256)
        string(MAKE_C_IDENTIFIER "${artifact_id}" artifact_key)
        set(locked_sha_${artifact_key} "${artifact_sha}")
    endforeach()

    macro(rawframe_locked_cache_object output artifact_id)
        string(MAKE_C_IDENTIFIER "${artifact_id}" _artifact_key)
        if(NOT DEFINED locked_sha_${_artifact_key})
            message(FATAL_ERROR "RF1544 artifact is not in the maintained lock: ${artifact_id}")
        endif()
        string(SUBSTRING "${locked_sha_${_artifact_key}}" 0 2 _cache_prefix)
        set(${output}
            "${CMAKE_SOURCE_DIR}/out/cache/objects/${_cache_prefix}/${locked_sha_${_artifact_key}}")
    endmacro()

    # Hostile archive inputs must fail inside the bounded validator with their
    # exact diagnostic before any extraction is published.
    foreach(case_entry IN ITEMS
            "traversal|RF1263" "unc|RF1263" "long_name|RF1263" "colon|RF1263"
            "absolute|RF1263" "case_collision|RF1267" "duplicate|RF1267"
            "deep|RF1264" "long_component|RF1266" "unexpected_root|RF1265"
            "missing_root|RF1276" "mixed_top|RF1318" "rootless_entry_count|RF1317"
            "rootless_shape|RF1319" "rootless_destination_exists|RF1321"
            "single_multi_entry|RF1272" "single_corrupt_payload|RF1225")
        string(REPLACE "|" ";" case_fields "${case_entry}")
        list(GET case_fields 0 case_name)
        list(GET case_fields 1 case_code)
        add_test(NAME "SyncFixtures.ArchiveNegative.${case_name}"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_CASE=${case_name}" "-DRF_SCRATCH=${scratch_root}/archive_negative"
                -P "${fixture_scripts}/archive_negative_cases.cmake")
        set_tests_properties("SyncFixtures.ArchiveNegative.${case_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "${case_code}" LABELS "security;archive" TIMEOUT 60)
    endforeach()

    # Offline cache negatives: empty and corrupt caches fail deterministically
    # without any network fallback.
    foreach(case_entry IN ITEMS "empty_cache|RF1249" "corrupt_cache|RF1225")
        string(REPLACE "|" ";" case_fields "${case_entry}")
        list(GET case_fields 0 case_name)
        list(GET case_fields 1 case_code)
        add_test(NAME "SyncFixtures.CacheNegative.${case_name}"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_CASE=${case_name}"
                -P "${fixture_scripts}/cache_negative_cases.cmake")
        set_tests_properties("SyncFixtures.CacheNegative.${case_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "${case_code}" LABELS "security;offline"
            RUN_SERIAL TRUE TIMEOUT 60)
    endforeach()

    add_test(NAME "SyncFixtures.ConfigureAcquisitionAudit"
        COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
            -P "${fixture_scripts}/configure_acquisition_audit.cmake")
    set_tests_properties("SyncFixtures.ConfigureAcquisitionAudit" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1543" LABELS "security;build" TIMEOUT 60)

    # Prepared-tree rollback recovery (2026-07-16 amendment): crash and
    # fault-injection states over the bounded fail-closed recovery contract.
    # Registered identically on both host lanes for parity; each case owns
    # its sandbox, so the cases run in parallel.
    foreach(case_name IN ITEMS
            fresh_publish stale_previous_clean restore_previous
            identity_mismatch mismatched_restore ambiguous_incoming
            no_recovery_root corrupt_marker containment_escape link_indirection)
        add_test(NAME "BootstrapFixtures.PreparedTreeRecovery.${case_name}"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_CASE=${case_name}"
                "-DRF_SCRATCH=${scratch_root}/prepared_tree_recovery"
                -P "${CMAKE_SOURCE_DIR}/cmake/bootstrap/tests/prepared_tree_recovery.cmake")
        set_tests_properties("BootstrapFixtures.PreparedTreeRecovery.${case_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1550" LABELS "security;bootstrap" TIMEOUT 60)
    endforeach()

    # TASK-0001 resolutions R1 and R3. Both admission rules take their input as
    # an argument, so each rejection reason is exercised directly. The two
    # admitted cases run in the same suite so a rule that rejects everything
    # cannot pass.
    foreach(case_entry IN ITEMS
            "cmake_release_candidate|RF1203" "cmake_vendor_build|RF1203"
            "cmake_other_stable_release|RF1204" "cmake_locked_identity_admitted|RF1573"
            "os_revision_below_floor|RF1501" "os_revision_not_integer|RF1501"
            "os_revision_at_and_above_floor_admitted|RF1573")
        string(REPLACE "|" ";" case_fields "${case_entry}")
        list(GET case_fields 0 case_name)
        list(GET case_fields 1 case_code)
        add_test(NAME "BootstrapFixtures.AdmissionRules.${case_name}"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_CASE=${case_name}"
                -P "${CMAKE_SOURCE_DIR}/cmake/bootstrap/tests/admission_rule_cases.cmake")
        set_tests_properties("BootstrapFixtures.AdmissionRules.${case_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "${case_code}" LABELS "security;bootstrap" TIMEOUT 60)
    endforeach()

    # TASK-0001 resolution R2 replaced frozen transport bytes with an exact
    # path, a version floor, and a vendor signature. Each condition carries a
    # case that proves it rejects. The tampered-binary case accepts any of the
    # signature-failure codes because SignTool stops before printing a signing
    # chain once the embedded signature no longer covers the bytes.
    foreach(case_entry IN ITEMS
            "absent_transport|RF1255" "unknown_signature_class|RF1256"
            "version_below_floor|RF1248" "unsigned_binary|RF144[123]")
        string(REPLACE "|" ";" case_fields "${case_entry}")
        list(GET case_fields 0 case_name)
        list(GET case_fields 1 case_code)
        if(case_name STREQUAL "unsigned_binary" AND NOT RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
            continue()
        endif()
        add_test(NAME "BootstrapFixtures.TransportAdmission.${case_name}"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_CASE=${case_name}"
                "-DRF_SCRATCH=${scratch_root}/transport_admission"
                -P "${CMAKE_SOURCE_DIR}/cmake/bootstrap/tests/transport_admission_cases.cmake")
        set_tests_properties("BootstrapFixtures.TransportAdmission.${case_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "${case_code}" LABELS "security;bootstrap" TIMEOUT 120)
    endforeach()

    # Stage-0 self-lock guard: a CMake running from beneath out/prepared keeps
    # its own image locked inside the tree the publish must replace, so the
    # publishing stages refuse it before performing any write. The command
    # deliberately runs the prepared CMake against the real Stage-0 script;
    # the guard fires before any filesystem or network effect.
    if(RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
        set(prepared_cmake_executable
            "${CMAKE_SOURCE_DIR}/out/prepared/${RAWFRAME_HOST_ID}/tools/cmake/bin/cmake.exe")
    else()
        set(prepared_cmake_executable
            "${CMAKE_SOURCE_DIR}/out/prepared/${RAWFRAME_HOST_ID}/tools/cmake/bin/cmake")
    endif()
    add_test(NAME "BootstrapFixtures.PreparedCMakeSelfLockGuard"
        COMMAND "${prepared_cmake_executable}"
            -DRF_OPERATION=sync "-DRF_HOST=${RAWFRAME_HOST_ID}"
            -P "${CMAKE_SOURCE_DIR}/cmake/bootstrap/sync.cmake")
    set_tests_properties("BootstrapFixtures.PreparedCMakeSelfLockGuard" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1323" LABELS "security;bootstrap" TIMEOUT 60)

    # Positive archive contracts over committed fixtures and locked artifacts.
    add_test(NAME "SyncFixtures.RootlessArchiveFixture"
        COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
            "-DRF_ARCHIVE=${fixture_archives}/benign.zip"
            "-DRF_EXPECTED_ENTRIES=3" "-DRF_EXPECTED_TOP_DIRECTORIES=1"
            "-DRF_EXPECTED_TOP_FILES=1"
            "-DRF_DESTINATION=${scratch_root}/rootless_benign"
            -P "${fixture_scripts}/rootless_archive.cmake")
    set_tests_properties("SyncFixtures.RootlessArchiveFixture" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1466" LABELS "archive" TIMEOUT 60)

    add_test(NAME "SyncFixtures.MultiRootArchive"
        COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
            "-DRF_ARCHIVE=${fixture_archives}/multiroot.zip"
            "-DRF_EXPECTED_ROOTS=alpha;beta"
            "-DRF_DESTINATION=${scratch_root}/multiroot"
            -P "${fixture_scripts}/multi_root_archive.cmake")
    set_tests_properties("SyncFixtures.MultiRootArchive" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1477" LABELS "archive" TIMEOUT 60)

    if(RAWFRAME_HOST_ID STREQUAL "windows-x86_64")
        rawframe_locked_cache_object(nasm_archive "tool.nasm.windows_x86_64")
        add_test(NAME "SyncFixtures.RootedArchive"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${nasm_archive}" "-DRF_EXPECTED_ROOT=nasm-3.01"
                "-DRF_DESTINATION=${scratch_root}/nasm"
                -P "${fixture_scripts}/archive.cmake")
        set_tests_properties("SyncFixtures.RootedArchive" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1489" LABELS "archive" TIMEOUT 120)

        rawframe_locked_cache_object(oracle_archive "tool.jsonschema_oracle.windows_x86_64")
        add_test(NAME "SyncFixtures.ArchiveListing"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${oracle_archive}"
                "-DRF_EXPECTED_ROOT=jsonschema-16.1.0-windows-x86_64"
                -P "${fixture_scripts}/archive_listing.cmake")
        set_tests_properties("SyncFixtures.ArchiveListing" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1479" LABELS "archive" TIMEOUT 60)

        rawframe_locked_cache_object(ninja_archive "tool.ninja.windows_x86_64")
        add_test(NAME "SyncFixtures.SingleFileArchive"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${ninja_archive}" "-DRF_EXPECTED_FILE=ninja.exe"
                "-DRF_EXPECTED_BYTES=603648"
                "-DRF_EXPECTED_SHA256=e52a7ad9538d9618c67a0bd777964e2eec8a30f68b810a2f6adce1f2daf847b8"
                "-DRF_DESTINATION=${scratch_root}/ninja"
                -P "${fixture_scripts}/single_file_archive.cmake")
        set_tests_properties("SyncFixtures.SingleFileArchive" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1485" LABELS "archive" TIMEOUT 60)

        rawframe_locked_cache_object(powershell_archive "tool.powershell.windows_x86_64")
        add_test(NAME "SyncFixtures.RootlessArchivePowerShell"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${powershell_archive}"
                "-DRF_EXPECTED_ENTRIES=986" "-DRF_EXPECTED_TOP_DIRECTORIES=18"
                "-DRF_EXPECTED_TOP_FILES=333"
                "-DRF_DESTINATION=${scratch_root}/powershell_rootless"
                -P "${fixture_scripts}/rootless_archive.cmake")
        set_tests_properties("SyncFixtures.RootlessArchivePowerShell" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1466" LABELS "archive"
            RUN_SERIAL TRUE TIMEOUT 600)

        set(prepared_tools "${CMAKE_SOURCE_DIR}/out/prepared/windows-x86_64/tools")
        rawframe_locked_cache_object(sourcemeta_key "authority.sourcemeta_release_key.data")
        rawframe_locked_cache_object(sourcemeta_checksums "tool.jsonschema_oracle.checksums")
        rawframe_locked_cache_object(sourcemeta_signature "tool.jsonschema_oracle.checksums_signature")
        # The Ubuntu image-checksum section of this fixture needs the
        # ubuntu-keyring package and SHA256SUMS objects that only the Linux
        # host lane acquires; the Linux registration passes
        # RF_UBUNTU_KEYRING_PACKAGE, RF_UBUNTU_CHECKSUMS, and
        # RF_UBUNTU_SIGNATURE to enable it.
        add_test(NAME "SyncFixtures.OpenpgpSidecars"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_GPG=${prepared_tools}/gnupg/bin/gpg.exe"
                "-DRF_GPGCONF=${prepared_tools}/gnupg/bin/gpgconf.exe"
                "-DRF_GPGV=${prepared_tools}/gnupg/bin/gpgv.exe"
                "-DRF_SOURCEMETA_KEY=${sourcemeta_key}"
                "-DRF_SOURCEMETA_CHECKSUMS=${sourcemeta_checksums}"
                "-DRF_SOURCEMETA_SIGNATURE=${sourcemeta_signature}"
                -P "${fixture_scripts}/openpgp_sidecars.cmake")
        set_tests_properties("SyncFixtures.OpenpgpSidecars" PROPERTIES
            LABELS "security;signature" RUN_SERIAL TRUE TIMEOUT 120)

        # No transport argument at all. Every input is a published verification
        # corpus artifact, so this fixture has no acquisition path to deny.
        add_test(NAME "SyncFixtures.ReleasePrimaries"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_HOST=windows-x86_64"
                -P "${fixture_scripts}/release_primaries.cmake")
        set_tests_properties("SyncFixtures.ReleasePrimaries" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1497" LABELS "security;signature" RUN_SERIAL TRUE TIMEOUT 300)

        add_test(NAME "SyncFixtures.LlvmClosure"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_HOST=windows-x86_64" "-DRF_TRANSPORT=${denied_transport}"
                -P "${fixture_scripts}/llvm_closure.cmake")
        set_tests_properties("SyncFixtures.LlvmClosure" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1481" LABELS "security;signature" TIMEOUT 300)

        add_test(NAME "SyncFixtures.Licenses"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                -P "${fixture_scripts}/licenses.cmake")
        set_tests_properties("SyncFixtures.Licenses" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1475" LABELS "license" TIMEOUT 120)

        include("${CMAKE_SOURCE_DIR}/cmake/sync/windows_host.cmake")
        add_test(NAME "SyncFixtures.Authenticode"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_HOST=windows-x86_64" "-DRF_TRANSPORT=${denied_transport}"
                "-DRF_SIGNTOOL=${RF_WINDOWS_HOST_SIGNTOOL}"
                -P "${fixture_scripts}/authenticode.cmake")
        set_tests_properties("SyncFixtures.Authenticode" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1499" LABELS "security;signature" TIMEOUT 120)

        add_test(NAME "SyncFixtures.WindowsDependencyAuthority"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                -P "${fixture_scripts}/windows_dependency_authority.cmake")
        set_tests_properties("SyncFixtures.WindowsDependencyAuthority" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1486" LABELS "repository;offline"
            RUN_SERIAL TRUE TIMEOUT 900)

        add_test(NAME "SyncFixtures.WindowsHost"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                -P "${fixture_scripts}/windows_host.cmake")
        set_tests_properties("SyncFixtures.WindowsHost" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1514" LABELS "repository;host"
            RUN_SERIAL TRUE TIMEOUT 300)

        # Forbidden provider substitutions must fail before any production
        # compilation with their exact configure-time diagnostic.
        foreach(case_entry IN ITEMS
                "msvc_frontend|RF1104" "vs_bundled_clang|RF1108" "wrong_sdk|RF1116"
                "wrong_vcpkg_baseline|RF1113" "ambient_provider|RF1112")
            string(REPLACE "|" ";" case_fields "${case_entry}")
            list(GET case_fields 0 case_name)
            list(GET case_fields 1 case_code)
            add_test(NAME "NegativeConfigure.${case_name}"
                COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                    "-DRF_CASE=${case_name}"
                    "-DRF_SCRATCH=${scratch_root}/negative_configure"
                    -P "${fixture_scripts}/negative_configure_cases.cmake")
            set_tests_properties("NegativeConfigure.${case_name}" PROPERTIES
                PASS_REGULAR_EXPRESSION "${case_code}" LABELS "security;build"
                RUN_SERIAL TRUE TIMEOUT 300)
        endforeach()
    elseif(RAWFRAME_HOST_ID STREQUAL "linux-x86_64")
        # Hostile symlink names survive listing validation by design; only the
        # post-extraction REAL_PATH containment sweep rejects the escaping
        # link, and materializing the link needs a native Linux host.
        add_test(NAME "SyncFixtures.ArchiveNegative.symlink_escape"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_CASE=symlink_escape"
                "-DRF_SCRATCH=${scratch_root}/archive_negative"
                -P "${fixture_scripts}/archive_negative_cases.cmake")
        set_tests_properties("SyncFixtures.ArchiveNegative.symlink_escape" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1269" LABELS "security;archive" TIMEOUT 60)

        # The signed Ubuntu Packages index is acquired by this lane's Stage-0
        # sync, so its exact locked gpgv/gpg/gpgconf/ubuntu-keyring records are
        # asserted here and nowhere else.
        rawframe_locked_cache_object(ubuntu_packages "host.ubuntu.noble_packages")
        add_test(NAME "BootstrapFixtures.LinuxPackageAuthority"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_PACKAGES_FILE=${ubuntu_packages}"
                -P "${CMAKE_SOURCE_DIR}/cmake/bootstrap/tests/linux_package_authority.cmake")
        set_tests_properties("BootstrapFixtures.LinuxPackageAuthority" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1312" LABELS "security;signature"
            TIMEOUT 60)

        # This lane possesses the ubuntu-keyring package and SHA256SUMS
        # objects, so the fixture's Ubuntu image-checksum section is enabled
        # alongside the Sourcemeta section the Windows lane already runs.
        set(prepared_tools "${CMAKE_SOURCE_DIR}/out/prepared/linux-x86_64/tools")
        rawframe_locked_cache_object(sourcemeta_key "authority.sourcemeta_release_key.data")
        rawframe_locked_cache_object(sourcemeta_checksums "tool.jsonschema_oracle.checksums")
        rawframe_locked_cache_object(sourcemeta_signature "tool.jsonschema_oracle.checksums_signature")
        rawframe_locked_cache_object(ubuntu_keyring_package "authority.ubuntu_archive_keyring.linux_all")
        rawframe_locked_cache_object(ubuntu_checksums "host.ubuntu.sha256sums")
        rawframe_locked_cache_object(ubuntu_checksums_signature "host.ubuntu.sha256sums_signature")
        add_test(NAME "SyncFixtures.OpenpgpSidecars"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_GPG=${prepared_tools}/gnupg/bin/gpg"
                "-DRF_GPGCONF=${prepared_tools}/gnupg/bin/gpgconf"
                "-DRF_GPGV=${prepared_tools}/gnupg/bin/gpgv"
                "-DRF_SOURCEMETA_KEY=${sourcemeta_key}"
                "-DRF_SOURCEMETA_CHECKSUMS=${sourcemeta_checksums}"
                "-DRF_SOURCEMETA_SIGNATURE=${sourcemeta_signature}"
                "-DRF_UBUNTU_KEYRING_PACKAGE=${ubuntu_keyring_package}"
                "-DRF_UBUNTU_CHECKSUMS=${ubuntu_checksums}"
                "-DRF_UBUNTU_SIGNATURE=${ubuntu_checksums_signature}"
                -P "${fixture_scripts}/openpgp_sidecars.cmake")
        set_tests_properties("SyncFixtures.OpenpgpSidecars" PROPERTIES
            LABELS "security;signature" RUN_SERIAL TRUE TIMEOUT 120)

        add_test(NAME "SyncFixtures.LinuxDependencyAuthority"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                -P "${fixture_scripts}/linux_dependency_authority.cmake")
        set_tests_properties("SyncFixtures.LinuxDependencyAuthority" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1588" LABELS "repository;offline"
            RUN_SERIAL TRUE TIMEOUT 900)

        add_test(NAME "SyncFixtures.LinuxHost"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                -P "${fixture_scripts}/linux_host.cmake")
        set_tests_properties("SyncFixtures.LinuxHost" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1559" LABELS "repository;host"
            RUN_SERIAL TRUE TIMEOUT 300)
    endif()
endfunction()
