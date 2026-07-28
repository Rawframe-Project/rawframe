cmake_minimum_required(VERSION 4.4)

if(NOT DEFINED RF_PACKAGES_FILE OR NOT EXISTS "${RF_PACKAGES_FILE}")
    message(FATAL_ERROR "RF1310 RF_PACKAGES_FILE is required")
endif()

cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH bootstrap_root)
include("${bootstrap_root}/common.cmake")
include("${bootstrap_root}/verifier.cmake")

file(SIZE "${RF_PACKAGES_FILE}" packages_bytes)
if(packages_bytes GREATER 67108864)
    message(FATAL_ERROR "RF1311 Packages fixture exceeds 64 MiB")
endif()
file(READ "${RF_PACKAGES_FILE}" packages_text LIMIT 67108865)

rf_require_debian_package_record(
    "${packages_text}" "gpgv" "2.4.8-4ubuntu3"
    "pool/main/g/gnupg2/gpgv_2.4.8-4ubuntu3_amd64.deb" "159866"
    "b07017fead25cc8997985e77059cc4c468f01cc39a85c98ec6aa61822719d3ba"
)
rf_require_debian_package_record(
    "${packages_text}" "gpg" "2.4.8-4ubuntu3"
    "pool/main/g/gnupg2/gpg_2.4.8-4ubuntu3_amd64.deb" "636780"
    "0f750a1157602bdb5fddd48d7b6b55f8b7665639df9e988f965a2cfe6418114f"
)
rf_require_debian_package_record(
    "${packages_text}" "gpgconf" "2.4.8-4ubuntu3"
    "pool/main/g/gnupg2/gpgconf_2.4.8-4ubuntu3_amd64.deb" "111222"
    "42744ee98bad9b691b18bdfbea94f1dd84652b0d98f009d725b76fd47468aa37"
)
rf_require_debian_package_record(
    "${packages_text}" "ubuntu-keyring" "2023.11.28.1build1"
    "pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1build1_all.deb" "11228"
    "c377ccf26964f4c206c05c0bc7adb708e031beb919bb9a0ff63af983d064cd66"
)

message(STATUS "RF1312 Linux signed-package authority fixture passed")
