cmake_minimum_required(VERSION 3.31)

if(NOT DEFINED RF_OPERATION OR NOT RF_OPERATION STREQUAL "sync")
    message(FATAL_ERROR "RF1201 Stage-0 accepts only -DRF_OPERATION=sync")
endif()
if(NOT DEFINED RF_HOST OR NOT RF_HOST MATCHES "^(windows-x86_64|linux-x86_64)$")
    message(FATAL_ERROR "RF1202 RF_HOST must be windows-x86_64 or linux-x86_64")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/common.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/transport.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/archive.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/verifier.cmake")

cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH cmake_root)
cmake_path(GET cmake_root PARENT_PATH repository_root)

# A CMake running from beneath out/prepared keeps its own executable image
# locked inside the tree the publish stages for replacement, so the staged
# rollback copy can never be removed. Refuse the publishing stages up front
# instead of failing at the final publish; the read-only verified_prepared
# stage is exempt because it must run through the prepared CMake.
if(NOT DEFINED RF_BOOTSTRAP_STAGE OR NOT RF_BOOTSTRAP_STAGE STREQUAL "verified_prepared")
    set(prepared_output_root "${repository_root}/out/prepared")
    if(EXISTS "${prepared_output_root}")
        file(REAL_PATH "${CMAKE_COMMAND}" running_cmake_path)
        file(REAL_PATH "${prepared_output_root}" prepared_output_root_real)
        cmake_path(IS_PREFIX prepared_output_root_real "${running_cmake_path}" NORMALIZE running_from_prepared)
        if(running_from_prepared)
            rf_bootstrap_fail("RF1323" "Stage-0 publishing stages must not run through a prepared-tree CMake; rerun with a CMake outside out/prepared")
        endif()
    endif()
endif()

rf_load_bootstrap_authority("${repository_root}" "${RF_HOST}")
# TASK-0001 resolution R3. Exactly one CMake identity is admitted: the locked
# 4.4.0 artifact, pre-staged and digest-verified before it runs. No ambient,
# vendor-bundled, or release-candidate CMake is admitted at any version.
rf_admit_bootstrap_cmake_version("${CMAKE_VERSION}" "${RF_cmake_version}" bootstrap_cmake_base_version)

if(RF_HOST STREQUAL "windows-x86_64")
    set(expected_transport_path "C:/Windows/System32/curl.exe")
    set(cmake_executable_relative "bin/cmake.exe")
else()
    set(expected_transport_path "/usr/bin/curl")
    set(cmake_executable_relative "bin/cmake")
endif()
if(NOT RF_transport_absolutePath STREQUAL expected_transport_path)
    rf_bootstrap_fail("RF1205" "bootstrap transport path differs from the exact host contract")
endif()
rf_verify_transport_executable(
    "${RF_transport_absolutePath}"
    "${RF_transport_minimumVersion}"
    "${RF_transport_vendorSignature}"
    transport_measured_version
)

set(bootstrap_root "${repository_root}/out/bootstrap/${RF_HOST}")
set(quarantine_root "${bootstrap_root}/quarantine")
file(MAKE_DIRECTORY "${quarantine_root}")
set(cmake_archive "${quarantine_root}/cmake-${RF_cmake_sha256}.archive")

if(NOT EXISTS "${cmake_archive}")
    set(prestaged_archive "${bootstrap_root}/prestaged/cmake-${RF_cmake_sha256}.archive")
    if(EXISTS "${prestaged_archive}")
        file(COPY_FILE "${prestaged_archive}" "${cmake_archive}" ONLY_IF_DIFFERENT)
        set(redirect_hops 0)
        set(transport_hosts "prestaged")
    else()
        rf_download_manually_redirected(
            "${RF_transport_absolutePath}"
            "${RF_cmake_origin}"
            "${cmake_archive}"
            "${RF_cmake_byteSize}"
            redirect_hops
            transport_hosts
        )
    endif()
endif()
rf_verify_file_identity("${cmake_archive}" "${RF_cmake_byteSize}" "${RF_cmake_sha256}" "quarantined CMake archive")

set(cmake_tree "${quarantine_root}/cmake-${RF_cmake_sha256}")
if(NOT EXISTS "${cmake_tree}")
    rf_extract_quarantine("${cmake_archive}" "${RF_cmake_archive_root}" "${cmake_tree}")
endif()
set(exact_cmake "${cmake_tree}/${RF_cmake_archive_root}/${cmake_executable_relative}")
if(NOT EXISTS "${exact_cmake}")
    rf_bootstrap_fail("RF1206" "quarantined exact CMake executable is missing")
endif()
execute_process(
    COMMAND "${exact_cmake}" --version
    RESULT_VARIABLE exact_version_result
    OUTPUT_VARIABLE exact_version_output
    ERROR_VARIABLE exact_version_error
    TIMEOUT 10
)
if(NOT exact_version_result EQUAL 0 OR NOT exact_version_output MATCHES "^cmake version ${RF_cmake_version}([\r\n]|$)")
    rf_bootstrap_fail("RF1207" "quarantined CMake version identity mismatch")
endif()

if(NOT DEFINED RF_BOOTSTRAP_STAGE)
    execute_process(
        COMMAND "${exact_cmake}"
            -DRF_OPERATION=sync
            -DRF_HOST=${RF_HOST}
            -DRF_BOOTSTRAP_STAGE=exact_cmake_quarantine
            -P "${CMAKE_CURRENT_LIST_FILE}"
        RESULT_VARIABLE reentry_result
    )
    if(NOT reentry_result EQUAL 0)
        rf_bootstrap_fail("RF1208" "exact CMake quarantine re-entry failed")
    endif()
    return()
endif()

if(NOT RF_BOOTSTRAP_STAGE MATCHES "^(exact_cmake_quarantine|verified_prepared)$")
    rf_bootstrap_fail("RF1209" "unknown bootstrap stage")
endif()
if(NOT CMAKE_VERSION STREQUAL RF_cmake_version)
    rf_bootstrap_fail("RF1210" "Stage-1 is not running through exact CMake")
endif()

set(host_tools_root "${repository_root}/out/prepared/${RF_HOST}/tools")
set(prepared_root "${host_tools_root}/cmake")
set(prepared_cmake "${prepared_root}/${cmake_executable_relative}")
if(RF_BOOTSTRAP_STAGE STREQUAL "verified_prepared")
    file(REAL_PATH "${CMAKE_COMMAND}" running_cmake)
    file(REAL_PATH "${prepared_cmake}" expected_cmake)
    if(NOT running_cmake STREQUAL expected_cmake OR NOT EXISTS "${prepared_root}/.rf-prepared.json")
        rf_bootstrap_fail("RF1212" "final bootstrap stage is not running through the verified prepared CMake")
    endif()
    file(MAKE_DIRECTORY "${repository_root}/out/reports/task-0001/${RF_HOST}")
    file(WRITE "${repository_root}/out/reports/task-0001/${RF_HOST}/sync.json.tmp"
        "{\n  \"host\": \"${RF_HOST}\",\n  \"cmakeVersion\": \"${RF_cmake_version}\",\n  \"cmakeArchiveSha256\": \"${RF_cmake_sha256}\",\n  \"verifierContractVersion\": 1,\n  \"state\": \"verified_prepared\"\n}\n"
    )
    file(RENAME
        "${repository_root}/out/reports/task-0001/${RF_HOST}/sync.json.tmp"
        "${repository_root}/out/reports/task-0001/${RF_HOST}/sync.json"
    )
    message(STATUS "RF1213 bootstrap verifier closure is verified and prepared")
    return()
endif()

if(RF_HOST STREQUAL "windows-x86_64")
    rf_quarantine_artifact("${repository_root}" "${bootstrap_root}" "${quarantine_root}" "${RF_transport_absolutePath}" "tool.archive_extractor.windows_x86_64" seven_zip)
    rf_extract_seven_zip("${seven_zip_path}" "${quarantine_root}/seven-zip-${seven_zip_sha256}" seven_zip_executable)
    rf_quarantine_artifact("${repository_root}" "${bootstrap_root}" "${quarantine_root}" "${RF_transport_absolutePath}" "tool.gnupg.windows_x86_64" gnupg)
    rf_quarantine_artifact("${repository_root}" "${bootstrap_root}" "${quarantine_root}" "${RF_transport_absolutePath}" "tool.gnupg.windows_x86_64_signature" gnupg_sig)
    rf_extract_gnupg_windows(
        "${seven_zip_executable}" "${gnupg_path}" "${quarantine_root}/gnupg-${gnupg_sha256}"
        gpg_executable gpgv_executable gnupg_distribution_keyring
    )
    rf_verify_gnupg_windows(
        "${gpg_executable}" "${gpgv_executable}" "${gnupg_distribution_keyring}"
        "${gnupg_sig_path}" "${gnupg_path}" "${quarantine_root}"
    )
else()
    rf_verify_gnupg_linux(
        "${repository_root}" "${bootstrap_root}" "${quarantine_root}" "${RF_transport_absolutePath}"
        gpg_executable gpgv_executable
    )
endif()

rf_verify_cmake_release(
    "${repository_root}" "${bootstrap_root}" "${quarantine_root}" "${RF_transport_absolutePath}"
    "${gpg_executable}" "${gpgv_executable}" "${RF_cmake_origin}" "${RF_cmake_sha256}"
)
rf_verify_cosign(
    "${repository_root}" "${bootstrap_root}" "${quarantine_root}" "${RF_transport_absolutePath}" "${RF_HOST}"
)

set(cache_root "${repository_root}/out/cache")
rf_publish_verified_file("${cache_root}" "${cmake_archive}" "${RF_cmake_sha256}" "${RF_cmake_byteSize}")
if(RF_HOST STREQUAL "windows-x86_64")
    rf_publish_locked_artifact("${repository_root}" "${cache_root}" "tool.archive_extractor.windows_x86_64" "${seven_zip_path}")
    rf_publish_locked_artifact("${repository_root}" "${cache_root}" "tool.gnupg.windows_x86_64" "${gnupg_path}")
    rf_publish_locked_artifact("${repository_root}" "${cache_root}" "tool.gnupg.windows_x86_64_signature" "${gnupg_sig_path}")
else()
    list(LENGTH RF_LINUX_VERIFIER_ARTIFACT_IDS linux_verifier_count)
    math(EXPR linux_verifier_last "${linux_verifier_count} - 1")
    foreach(index RANGE 0 ${linux_verifier_last})
        list(GET RF_LINUX_VERIFIER_ARTIFACT_IDS ${index} artifact_id)
        list(GET RF_LINUX_VERIFIER_ARTIFACT_PATHS ${index} artifact_path)
        rf_publish_locked_artifact("${repository_root}" "${cache_root}" "${artifact_id}" "${artifact_path}")
    endforeach()
endif()
list(LENGTH RF_CMAKE_SIDECAR_IDS sidecar_count)
math(EXPR sidecar_last "${sidecar_count} - 1")
foreach(index RANGE 0 ${sidecar_last})
    list(GET RF_CMAKE_SIDECAR_IDS ${index} artifact_id)
    list(GET RF_CMAKE_SIDECAR_PATHS ${index} artifact_path)
    rf_publish_locked_artifact("${repository_root}" "${cache_root}" "${artifact_id}" "${artifact_path}")
endforeach()
list(LENGTH RF_COSIGN_ARTIFACT_IDS cosign_count)
math(EXPR cosign_last "${cosign_count} - 1")
foreach(index RANGE 0 ${cosign_last})
    list(GET RF_COSIGN_ARTIFACT_IDS ${index} artifact_id)
    list(GET RF_COSIGN_ARTIFACT_PATHS ${index} artifact_path)
    rf_publish_locked_artifact("${repository_root}" "${cache_root}" "${artifact_id}" "${artifact_path}")
endforeach()

if(RF_HOST STREQUAL "windows-x86_64")
    set(seven_zip_prepared_source "${quarantine_root}/seven-zip-${seven_zip_sha256}")
    set(gnupg_prepared_source "${quarantine_root}/gnupg-${gnupg_sha256}")
else()
    set(seven_zip_prepared_source "${RF_LINUX_SEVEN_ZIP_TREE}")
    set(gnupg_prepared_source "${quarantine_root}/prepared-gnupg")
    file(REMOVE_RECURSE "${gnupg_prepared_source}")
    file(MAKE_DIRECTORY "${gnupg_prepared_source}/bin" "${gnupg_prepared_source}/share/gnupg")
    file(COPY_FILE "${gpg_executable}" "${gnupg_prepared_source}/bin/gpg")
    file(COPY_FILE "${gpgv_executable}" "${gnupg_prepared_source}/bin/gpgv")
    file(COPY_FILE "${RF_LINUX_ARCHIVE_KEYRING}" "${gnupg_prepared_source}/share/gnupg/ubuntu-archive-keyring.gpg")
endif()

set(cosign_prepared_source "${quarantine_root}/prepared-cosign")
file(REMOVE_RECURSE "${cosign_prepared_source}")
file(MAKE_DIRECTORY "${cosign_prepared_source}/bin" "${cosign_prepared_source}/share")
if(RF_HOST STREQUAL "windows-x86_64")
    set(cosign_prepared_name "cosign.exe")
else()
    set(cosign_prepared_name "cosign")
endif()
file(COPY_FILE "${RF_COSIGN_PATH}" "${cosign_prepared_source}/bin/${cosign_prepared_name}")
list(GET RF_COSIGN_ARTIFACT_PATHS 1 cosign_bundle_path)
file(COPY_FILE "${cosign_bundle_path}" "${cosign_prepared_source}/share/cosign.sigstore.json")
list(GET RF_COSIGN_ARTIFACT_PATHS 2 sigstore_trusted_root_path)
file(COPY_FILE "${sigstore_trusted_root_path}" "${cosign_prepared_source}/share/trusted_root.json")

set(prepared_recovery_root "${repository_root}/out/prepared/${RF_HOST}")
rf_publish_prepared_tree(
    "${seven_zip_prepared_source}" "${host_tools_root}/seven_zip"
    "{\n  \"host\": \"${RF_HOST}\",\n  \"tool\": \"tool.archive_extractor\",\n  \"verifierContractVersion\": 1\n}\n"
    "${prepared_recovery_root}"
)
rf_publish_prepared_tree(
    "${gnupg_prepared_source}" "${host_tools_root}/gnupg"
    "{\n  \"host\": \"${RF_HOST}\",\n  \"tool\": \"tool.gnupg\",\n  \"verifierContractVersion\": 1\n}\n"
    "${prepared_recovery_root}"
)
rf_publish_prepared_tree(
    "${cosign_prepared_source}" "${host_tools_root}/cosign"
    "{\n  \"host\": \"${RF_HOST}\",\n  \"tool\": \"tool.cosign\",\n  \"verifierContractVersion\": 1\n}\n"
    "${prepared_recovery_root}"
)
rf_publish_prepared_tree(
    "${cmake_tree}/${RF_cmake_archive_root}" "${prepared_root}"
    "{\n  \"host\": \"${RF_HOST}\",\n  \"tool\": \"tool.cmake\",\n  \"version\": \"${RF_cmake_version}\",\n  \"archiveSha256\": \"${RF_cmake_sha256}\",\n  \"verifierContractVersion\": 1\n}\n"
    "${prepared_recovery_root}"
)

execute_process(
    COMMAND "${prepared_cmake}"
        -DRF_OPERATION=sync -DRF_HOST=${RF_HOST} -DRF_BOOTSTRAP_STAGE=verified_prepared
        -P "${CMAKE_CURRENT_LIST_FILE}"
    RESULT_VARIABLE prepared_reentry_result
)
if(NOT prepared_reentry_result EQUAL 0)
    rf_bootstrap_fail("RF1216" "verified prepared CMake re-entry failed")
endif()
return()
