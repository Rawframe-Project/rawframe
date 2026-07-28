cmake_minimum_required(VERSION 4.4.0)

# The Sourcemeta section always runs. The Ubuntu image-checksum section runs
# only when its arguments are provided, because the ubuntu-keyring package,
# SHA256SUMS, and SHA256SUMS.gpg objects are acquired by the Linux host lane;
# the Windows lane never possesses them and tests perform no acquisition.
foreach(argument IN ITEMS RF_REPOSITORY_ROOT RF_GPG RF_GPGV RF_GPGCONF RF_SOURCEMETA_KEY
                          RF_SOURCEMETA_CHECKSUMS RF_SOURCEMETA_SIGNATURE)
    if(NOT DEFINED ${argument})
        message(FATAL_ERROR "RF1494 ${argument} is required")
    endif()
endforeach()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/openpgp.cmake")
set(work_root "${RF_REPOSITORY_ROOT}/out/sync/tests")
file(MAKE_DIRECTORY "${work_root}")

rf_prepare_release_keyring(
    "${RF_GPG}" "${RF_GPGCONF}" "${RF_SOURCEMETA_KEY}"
    "F1CCCE7BD9D52CB76FE05C9B9C6328B7F7D5AA04" "${work_root}" "sourcemeta" sourcemeta_keyring
)
rf_verify_detached_openpgp(
    "${RF_GPGV}" "${sourcemeta_keyring}" "${RF_SOURCEMETA_SIGNATURE}" "${RF_SOURCEMETA_CHECKSUMS}"
    "74349365D546399E77BE3943C92F4034F60CEC38" "Sourcemeta v16.1.0 checksums"
)
rf_require_exact_checksum_line(
    "${RF_SOURCEMETA_CHECKSUMS}"
    "SHA256 (jsonschema-16.1.0-windows-x86_64.zip) = 986aa0a16f0b0ef103487dd4e65be833c358e07603bf336ad0a598feb69993da"
    "Sourcemeta Windows oracle"
)
rf_require_exact_checksum_line(
    "${RF_SOURCEMETA_CHECKSUMS}"
    "SHA256 (jsonschema-16.1.0-linux-x86_64.zip) = 96b214be67bf25c6184f1d009a94e082d1eaa83787a8f1878607aebf3185668e"
    "Sourcemeta Linux oracle"
)
if(DEFINED RF_UBUNTU_KEYRING_PACKAGE)
    foreach(argument IN ITEMS RF_UBUNTU_CHECKSUMS RF_UBUNTU_SIGNATURE)
        if(NOT DEFINED ${argument})
            message(FATAL_ERROR "RF1494 ${argument} is required")
        endif()
    endforeach()
    # gpgv consumes an OpenPGP keyring, not a Debian package: extract the
    # locked inner archive keyring from the ubuntu-keyring package and verify
    # its exact locked identity before trusting any signature it validates.
    include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/verifier.cmake")
    rf_load_required_file(
        "${RF_REPOSITORY_ROOT}" "authority.ubuntu_archive_keyring.linux_all"
        "usr/share/keyrings/ubuntu-archive-keyring.gpg" keyring_inner
    )
    rf_extract_debian_payload(
        "${RF_UBUNTU_KEYRING_PACKAGE}" "${work_root}/ubuntu-keyring-payload"
        "usr/share/keyrings/ubuntu-archive-keyring.gpg"
        "${keyring_inner_byteSize}" "${keyring_inner_sha256}" ubuntu_keyring
    )
    rf_verify_detached_openpgp(
        "${RF_GPGV}" "${ubuntu_keyring}" "${RF_UBUNTU_SIGNATURE}" "${RF_UBUNTU_CHECKSUMS}"
        "843938DF228D22F7B3742BC0D94AA3F0EFE21092" "Ubuntu 26.04 image checksums"
    )
    rf_require_exact_checksum_line(
        "${RF_UBUNTU_CHECKSUMS}"
        "dec49008a71f6098d0bcfc822021f4d042d5f2db279e4d75bdd981304f1ca5d9 *ubuntu-26.04-live-server-amd64.iso"
        "Ubuntu 26.04 server image"
    )
endif()
message(STATUS "RF1495 OpenPGP sidecar fixtures passed")

