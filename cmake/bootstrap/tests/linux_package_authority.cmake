cmake_minimum_required(VERSION 4.4)

if(NOT DEFINED RF_PACKAGES_FILE OR NOT EXISTS "${RF_PACKAGES_FILE}")
    message(FATAL_ERROR "RF1310 RF_PACKAGES_FILE is required")
endif()
if(NOT DEFINED RF_REPOSITORY_ROOT OR NOT IS_DIRECTORY "${RF_REPOSITORY_ROOT}")
    message(FATAL_ERROR "RF1310 RF_REPOSITORY_ROOT is required")
endif()

cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH bootstrap_root)
include("${bootstrap_root}/common.cmake")
include("${bootstrap_root}/verifier.cmake")

# The locked artifact is the compressed index Canonical publishes, so the
# fixture reads it through the same decompression the host probe uses instead of
# treating the stored bytes as text.
rf_read_debian_packages_index(
    "${RF_REPOSITORY_ROOT}/out/prepared/linux-x86_64/tools/seven_zip/7zz"
    "${RF_PACKAGES_FILE}"
    "${RF_REPOSITORY_ROOT}/out/sync/linux-x86_64/package-authority-fixture"
    packages_text)

rf_require_debian_package_record(
    "${packages_text}" "gpgv" "2.4.4-2ubuntu17"
    "pool/main/g/gnupg2/gpgv_2.4.4-2ubuntu17_amd64.deb" "157184"
    "59303f676f8002f2c82698ba76037f8dab4debad2c19619bf4d78bb817201a27"
)
rf_require_debian_package_record(
    "${packages_text}" "gpg" "2.4.4-2ubuntu17"
    "pool/main/g/gnupg2/gpg_2.4.4-2ubuntu17_amd64.deb" "564966"
    "2329ce5333698fe40e6bf2f627842f589cfe1fcd2ab3038c1491f2bfc88546f7"
)
rf_require_debian_package_record(
    "${packages_text}" "gpgconf" "2.4.4-2ubuntu17"
    "pool/main/g/gnupg2/gpgconf_2.4.4-2ubuntu17_amd64.deb" "103228"
    "b165cb87da51dba16fb091fdd7feba6e50a9a81fd393a1c6a1e8d7d25a6bc95f"
)
rf_require_debian_package_record(
    "${packages_text}" "ubuntu-keyring" "2023.11.28.1"
    "pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1_all.deb" "11124"
    "36de43b15853ccae0028e9a767613770c704833f82586f28eb262f0311adb8a8"
)

message(STATUS "RF1312 Linux signed-package authority fixture passed")
