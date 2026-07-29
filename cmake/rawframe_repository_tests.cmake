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

    # The next three fixtures read only committed indexes, locked artifacts, and
    # the published verification corpus, so each one is registered once and takes
    # the host as an argument. Keeping a single registration is what stops the
    # two lanes from drifting into different coverage.
    #
    # No transport argument at all. Every input is a published verification
    # corpus artifact, so this fixture has no acquisition path to deny.
    add_test(NAME "SyncFixtures.ReleasePrimaries"
        COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
            "-DRF_HOST=${RAWFRAME_HOST_ID}"
            -P "${fixture_scripts}/release_primaries.cmake")
    set_tests_properties("SyncFixtures.ReleasePrimaries" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1497" LABELS "security;signature" RUN_SERIAL TRUE TIMEOUT 300)

    add_test(NAME "SyncFixtures.LlvmClosure"
        COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
            "-DRF_HOST=${RAWFRAME_HOST_ID}" "-DRF_TRANSPORT=${denied_transport}"
            -P "${fixture_scripts}/llvm_closure.cmake")
    set_tests_properties("SyncFixtures.LlvmClosure" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1481" LABELS "security;signature" TIMEOUT 300)

    add_test(NAME "SyncFixtures.Licenses"
        COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
            -P "${fixture_scripts}/licenses.cmake")
    set_tests_properties("SyncFixtures.Licenses" PROPERTIES
        PASS_REGULAR_EXPRESSION "RF1475" LABELS "license" TIMEOUT 120)

    # Every delivered command, run once against this repository on this host.
    # The unit suites drive the same code through scratch and synthetic roots,
    # which is what lets them break one rule at a time, but that means no test
    # had ever executed a delivered command against the real tree. A defect that
    # only appears against real inputs on one host was invisible to all of them.
    foreach(command_entry IN ITEMS
            "ValidateRepository|validate;repository"
            "GraphRepository|graph;repository"
            "InspectSourceOwnership|inspect;source-ownership"
            "ReviewLicenses|review;licenses"
            "AuditPaths|audit;paths"
            "AuditShippingClosure|audit;shipping-closure")
        string(REPLACE "|" ";" command_fields "${command_entry}")
        list(GET command_fields 0 command_name)
        list(GET command_fields 1 command_operation)
        list(GET command_fields 2 command_subject)
        add_test(NAME "Command.${command_name}"
            COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>"
                "${command_operation}" "${command_subject}"
                --root "${CMAKE_SOURCE_DIR}" --format json)
        set_tests_properties("Command.${command_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "\"ok\":true" LABELS "repository" TIMEOUT 300)
    endforeach()

    # The two record commands take an input record instead of only a root, so
    # they cannot join the loop above. Both are driven against the committed
    # fixtures rather than a scratch file: canonicalize reads the authored form
    # and validate reads the canonical form, which is the pairing that would
    # break first if the committed golden bytes ever drifted from the code.
    foreach(record_entry IN ITEMS
            "CanonicalizeRecord|canonicalize|records/raw-run-receipt-authored.json"
            "ValidateRecord|validate|canonical/raw-run-receipt-v1.canonical.json")
        string(REPLACE "|" ";" record_fields "${record_entry}")
        list(GET record_fields 0 record_name)
        list(GET record_fields 1 record_operation)
        list(GET record_fields 2 record_relative)
        add_test(NAME "Command.${record_name}"
            COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>"
                "${record_operation}" record
                --root "${CMAKE_SOURCE_DIR}"
                --record "${CMAKE_SOURCE_DIR}/tools/rf_evidence/tests/fixtures/evidence/${record_relative}"
                --format json)
        set_tests_properties("Command.${record_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "\"ok\":true" LABELS "repository" TIMEOUT 300)
    endforeach()

    # The strongest statement of the decision that `validate` cannot write a
    # corrected form is that it has nowhere to write one. A report destination
    # is refused rather than ignored, so the absence stays observable.
    add_test(NAME "Command.ValidateRecordRefusesAReportDestination"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" validate record
            --root "${CMAKE_SOURCE_DIR}"
            --record "${CMAKE_SOURCE_DIR}/tools/rf_evidence/tests/fixtures/evidence/canonical/raw-run-receipt-v1.canonical.json"
            --report "${CMAKE_CURRENT_BINARY_DIR}/must-not-be-written.json" --format json)
    set_tests_properties("Command.ValidateRecordRefusesAReportDestination" PROPERTIES
        PASS_REGULAR_EXPRESSION "record operations write no report"
        LABELS "repository;security" TIMEOUT 300)

    # The store at the process level. The unit suite drives it against scratch
    # space; these cases prove the installed command derives the same path in
    # the repository's own store and hands the bytes back unaltered, which is
    # where a text-mode standard output would corrupt them.
    set(rawframe_blob_fixture
        "tools/rf_evidence/tests/fixtures/evidence/canonical/raw-run-receipt-v1.canonical.json")
    set(rawframe_blob_digest
        "sha256:3dc74eaae771300011a1a4ed6864854fcbe98575918b9cda2978fca701088bc3")
    set(rawframe_blob_media "application/vnd.rawframe.evidence.raw-run-receipt.v1+json")

    add_test(NAME "Command.PutBlob"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" put blob
            --root "${CMAKE_SOURCE_DIR}"
            --source "${rawframe_blob_fixture}"
            --media "${rawframe_blob_media}")
    set_tests_properties("Command.PutBlob" PROPERTIES
        PASS_REGULAR_EXPRESSION "\"digest\":\"${rawframe_blob_digest}\""
        FIXTURES_SETUP rawframe_blob_seed LABELS "repository" TIMEOUT 300)

    # Putting the same content again must report the identical descriptor. The
    # published blob is immutable, so the second run publishes nothing and
    # verifies what is already there.
    add_test(NAME "Command.PutBlobIsIdempotent"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" put blob
            --root "${CMAKE_SOURCE_DIR}"
            --source "${rawframe_blob_fixture}"
            --media "${rawframe_blob_media}")
    set_tests_properties("Command.PutBlobIsIdempotent" PROPERTIES
        PASS_REGULAR_EXPRESSION "\"digest\":\"${rawframe_blob_digest}\""
        FIXTURES_REQUIRED rawframe_blob_seed LABELS "repository" TIMEOUT 300)

    add_test(NAME "Command.VerifyBlob"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" verify blob
            --root "${CMAKE_SOURCE_DIR}"
            --digest "${rawframe_blob_digest}"
            --media "${rawframe_blob_media}")
    set_tests_properties("Command.VerifyBlob" PROPERTIES
        PASS_REGULAR_EXPRESSION "\"byteLength\":2852"
        FIXTURES_REQUIRED rawframe_blob_seed LABELS "repository" TIMEOUT 300)

    # The stored bytes come back through the process boundary. Byte exactness
    # over control and high bytes is held by the unit suite, which can compare
    # whole buffers; what this case adds is that the installed command emits the
    # record itself rather than a summary of it.
    add_test(NAME "Command.GetBlobReturnsTheStoredRecord"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" get blob
            --root "${CMAKE_SOURCE_DIR}"
            --digest "${rawframe_blob_digest}")
    set_tests_properties("Command.GetBlobReturnsTheStoredRecord" PROPERTIES
        PASS_REGULAR_EXPRESSION "\"provenance\":\"diagnostic_untrusted\""
        FIXTURES_REQUIRED rawframe_blob_seed LABELS "repository" TIMEOUT 300)

    add_test(NAME "Command.VerifyBlobRejectsAMalformedDigest"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" verify blob
            --root "${CMAKE_SOURCE_DIR}"
            --digest "sha256:../../../../etc/passwd"
            --media "${rawframe_blob_media}" --format json)
    set_tests_properties("Command.VerifyBlobRejectsAMalformedDigest" PROPERTIES
        PASS_REGULAR_EXPRESSION "invalid_digest" LABELS "repository;security" TIMEOUT 300)

    add_test(NAME "Command.PutBlobRejectsASourceOutsideTheRepository"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" put blob
            --root "${CMAKE_SOURCE_DIR}"
            --source "../outside-the-repository.json"
            --media "${rawframe_blob_media}" --format json)
    set_tests_properties("Command.PutBlobRejectsASourceOutsideTheRepository" PROPERTIES
        PASS_REGULAR_EXPRESSION "invalid_path" LABELS "repository;security" TIMEOUT 300)

    # A store operation writes exactly one place, the path its digest derives.
    add_test(NAME "Command.PutBlobRefusesAReportDestination"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" put blob
            --root "${CMAKE_SOURCE_DIR}"
            --source "${rawframe_blob_fixture}"
            --media "${rawframe_blob_media}"
            --report "${CMAKE_CURRENT_BINARY_DIR}/must-not-be-written.json" --format json)
    set_tests_properties("Command.PutBlobRefusesAReportDestination" PROPERTIES
        PASS_REGULAR_EXPRESSION "store operations write no report"
        LABELS "repository;security" TIMEOUT 300)

    # Kept apart from the loop above because it takes the host rather than a
    # subject, and because it is the one command that hashes the whole locked
    # closure and runs the prepared signing tool.
    add_test(NAME "Command.VerifyOffline"
        COMMAND "$<TARGET_FILE:rawframe_tool_rf_evidence>" verify-offline
            --root "${CMAKE_SOURCE_DIR}" "--host" "${RAWFRAME_HOST_ID}" --format json)
    set_tests_properties("Command.VerifyOffline" PROPERTIES
        PASS_REGULAR_EXPRESSION "\"ok\":true" LABELS "repository;offline"
        RUN_SERIAL TRUE TIMEOUT 900)

    # A substituted dependency provider must be rejected before any production
    # compilation. The installed-tree authority is checked ahead of the
    # host-specific section of the policy, so both cases apply to every lane and
    # each one configures that lane's own preset.
    foreach(case_entry IN ITEMS "wrong_vcpkg_baseline|RF1113" "ambient_provider|RF1112")
        string(REPLACE "|" ";" case_fields "${case_entry}")
        list(GET case_fields 0 case_name)
        list(GET case_fields 1 case_code)
        add_test(NAME "NegativeConfigure.${case_name}"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_HOST=${RAWFRAME_HOST_ID}" "-DRF_CASE=${case_name}"
                "-DRF_SCRATCH=${scratch_root}/negative_configure"
                -P "${fixture_scripts}/negative_configure_cases.cmake")
        set_tests_properties("NegativeConfigure.${case_name}" PROPERTIES
            PASS_REGULAR_EXPRESSION "${case_code}" LABELS "security;build"
            RUN_SERIAL TRUE TIMEOUT 300)
    endforeach()

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

        # Forbidden toolchain substitutions must fail before any production
        # compilation with their exact configure-time diagnostic. These three
        # name Windows providers; the host-neutral provider cases are registered
        # once for both lanes above.
        foreach(case_entry IN ITEMS
                "msvc_frontend|RF1104" "vs_bundled_clang|RF1108" "wrong_sdk|RF1116")
            string(REPLACE "|" ";" case_fields "${case_entry}")
            list(GET case_fields 0 case_name)
            list(GET case_fields 1 case_code)
            add_test(NAME "NegativeConfigure.${case_name}"
                COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                    "-DRF_HOST=${RAWFRAME_HOST_ID}" "-DRF_CASE=${case_name}"
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

        # The positive archive contracts run against this lane's own locked
        # artifacts rather than the other host's. The rooted case deliberately
        # uses the CMake tarball, because it is the only committed lock entry
        # whose format is tar_gz and no other fixture proves that reader.
        rawframe_locked_cache_object(cmake_archive "tool.cmake.linux_x86_64")
        add_test(NAME "SyncFixtures.RootedArchive"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${cmake_archive}"
                "-DRF_EXPECTED_ROOT=cmake-4.4.0-linux-x86_64"
                "-DRF_DESTINATION=${scratch_root}/cmake_rooted"
                -P "${fixture_scripts}/archive.cmake")
        set_tests_properties("SyncFixtures.RootedArchive" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1489" LABELS "archive"
            RUN_SERIAL TRUE TIMEOUT 600)

        rawframe_locked_cache_object(oracle_archive "tool.jsonschema_oracle.linux_x86_64")
        add_test(NAME "SyncFixtures.ArchiveListing"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${oracle_archive}"
                "-DRF_EXPECTED_ROOT=jsonschema-16.1.0-linux-x86_64"
                -P "${fixture_scripts}/archive_listing.cmake")
        set_tests_properties("SyncFixtures.ArchiveListing" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1479" LABELS "archive" TIMEOUT 60)

        rawframe_locked_cache_object(ninja_archive "tool.ninja.linux_x86_64")
        add_test(NAME "SyncFixtures.SingleFileArchive"
            COMMAND "${CMAKE_COMMAND}" "${repository_root_argument}"
                "-DRF_ARCHIVE=${ninja_archive}" "-DRF_EXPECTED_FILE=ninja"
                "-DRF_EXPECTED_BYTES=290928"
                "-DRF_EXPECTED_SHA256=607e668f90dd6cd82e1a42ae572647ad1b1fd43063964295b9547836d8c15d99"
                "-DRF_DESTINATION=${scratch_root}/ninja"
                -P "${fixture_scripts}/single_file_archive.cmake")
        set_tests_properties("SyncFixtures.SingleFileArchive" PROPERTIES
            PASS_REGULAR_EXPRESSION "RF1485" LABELS "archive" TIMEOUT 60)

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
