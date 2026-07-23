cmake_minimum_required(VERSION 4.4.0)

if(NOT DEFINED RF_REPOSITORY_ROOT OR NOT DEFINED RF_LLVM_PROVENANCE_FIXTURE OR
   NOT DEFINED RF_LLVM_ARTIFACT_NAME OR NOT DEFINED RF_LLVM_ARTIFACT_SHA256)
    message(FATAL_ERROR "RF1490 LLVM provenance fixture arguments are required")
endif()

include("${RF_REPOSITORY_ROOT}/cmake/bootstrap/common.cmake")
include("${RF_REPOSITORY_ROOT}/cmake/sync/llvm.cmake")
rf_verify_llvm_provenance_semantics(
    "${RF_LLVM_PROVENANCE_FIXTURE}"
    "${RF_LLVM_ARTIFACT_NAME}"
    "${RF_LLVM_ARTIFACT_SHA256}"
)
if(DEFINED RF_COSIGN_EXECUTABLE OR DEFINED RF_SIGSTORE_TRUSTED_ROOT)
    if(NOT DEFINED RF_COSIGN_EXECUTABLE OR NOT DEFINED RF_SIGSTORE_TRUSTED_ROOT)
        message(FATAL_ERROR "RF1492 both Sigstore fixture arguments are required")
    endif()
    rf_verify_llvm_sigstore(
        "${RF_COSIGN_EXECUTABLE}"
        "${RF_SIGSTORE_TRUSTED_ROOT}"
        "${RF_LLVM_PROVENANCE_FIXTURE}"
        "${RF_LLVM_ARTIFACT_SHA256}"
    )
endif()
if(DEFINED RF_GPG_EXECUTABLE OR DEFINED RF_LLVM_RELEASE_KEYS)
    if(NOT DEFINED RF_GPG_EXECUTABLE OR NOT DEFINED RF_LLVM_RELEASE_KEYS)
        message(FATAL_ERROR "RF1493 both OpenPGP fixture arguments are required")
    endif()
    rf_prepare_llvm_keyring(
        "${RF_GPG_EXECUTABLE}"
        "${RF_LLVM_RELEASE_KEYS}"
        "${RF_REPOSITORY_ROOT}/out/sync/tests"
        fixture_keyring
    )
endif()
message(STATUS "RF1491 LLVM provenance semantic fixture passed")
