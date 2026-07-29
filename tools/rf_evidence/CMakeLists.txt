find_package(simdjson 4.6.4 CONFIG REQUIRED)
find_package(OpenSSL 3.5.7 EXACT REQUIRED COMPONENTS Crypto)

add_library(rawframe_tool_rf_evidence_private STATIC)
target_sources(rawframe_tool_rf_evidence_private PRIVATE
    src/blob_store.cpp
    src/evidence_set.cpp
    src/canonical_json.cpp
    src/command.cpp
    src/dependency_authority.cpp
    src/descriptor.cpp
    src/diagnostic.cpp
    src/evaluation_policy.cpp
    src/evaluator.cpp
    src/file_reader.cpp
    src/file_security.cpp
    src/metric_registry.cpp
    src/record_command.cpp
    src/record_gate.cpp
    src/json_policy.cpp
    src/license_review.cpp
    src/offline_verifier.cpp
    src/path_audit.cpp
    src/path_policy.cpp
    src/process_runner.cpp
    src/raw_run_receipt.cpp
    src/report_writer.cpp
    src/repository_validator.cpp
    src/schema_oracle.cpp
    src/sha256.cpp
    src/shipping_closure.cpp
    src/source_inspector.cpp
    src/store_command.cpp
)
target_include_directories(rawframe_tool_rf_evidence_private PUBLIC src)
target_link_libraries(rawframe_tool_rf_evidence_private PUBLIC
    rawframe::compiler_policy
    simdjson::simdjson
    OpenSSL::Crypto
)
set_target_properties(rawframe_tool_rf_evidence_private PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

add_executable(rawframe_tool_rf_evidence src/main.cpp)
target_link_libraries(rawframe_tool_rf_evidence PRIVATE rawframe_tool_rf_evidence_private)
set_target_properties(rawframe_tool_rf_evidence PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    OUTPUT_NAME rf-evidence
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tools"
)

if(RAWFRAME_BUILD_TESTS)
    find_package(GTest 1.17.0 EXACT CONFIG REQUIRED)
    add_subdirectory(tests)
endif()

if(RAWFRAME_ENABLE_ANALYSIS)
    if(NOT DEFINED RAWFRAME_CLANG_FORMAT_EXECUTABLE OR
       NOT EXISTS "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}")
        message(FATAL_ERROR "RF1120 the preset's locked clang-format executable is absent")
    endif()
    set(rawframe_tool_rf_evidence_maintained_sources
        src/blob_store.cpp
        src/blob_store.h
        src/evidence_set.cpp
        src/evidence_set.h
        src/canonical_json.cpp
        src/canonical_json.h
        src/command.cpp
        src/command.h
        src/dependency_authority.cpp
        src/dependency_authority.h
        src/descriptor.cpp
        src/descriptor.h
        src/diagnostic.cpp
        src/diagnostic.h
        src/evaluation_policy.cpp
        src/evaluation_policy.h
        src/evaluator.cpp
        src/evaluator.h
        src/failure.h
        src/file_reader.cpp
        src/file_reader.h
        src/file_security.cpp
        src/file_security.h
        src/record_command.cpp
        src/record_command.h
        src/record_gate.cpp
        src/record_gate.h
        src/json_policy.cpp
        src/json_policy.h
        src/license_review.cpp
        src/license_review.h
        src/main.cpp
        src/metric_registry.cpp
        src/metric_registry.h
        src/offline_verifier.cpp
        src/offline_verifier.h
        src/path_audit.cpp
        src/path_audit.h
        src/path_policy.cpp
        src/path_policy.h
        src/process_runner.cpp
        src/process_runner.h
        src/raw_run_receipt.cpp
        src/raw_run_receipt.h
        src/report_writer.cpp
        src/report_writer.h
        src/repository_validator.cpp
        src/repository_validator.h
        src/schema_oracle.cpp
        src/schema_oracle.h
        src/sha256.cpp
        src/sha256.h
        src/shipping_closure.cpp
        src/shipping_closure.h
        src/source_inspector.cpp
        src/source_inspector.h
        src/store_command.cpp
        src/store_command.h
        tests/blob_store_test.cpp
        tests/evaluation_policy_test.cpp
        tests/evaluator_test.cpp
        tests/evidence_set_test.cpp
        tests/metric_registry_test.cpp
        tests/record_gate_test.cpp
        tests/canonical_json_test.cpp
        tests/command_test.cpp
        tests/dependency_authority_test.cpp
        tests/descriptor_test.cpp
        tests/diagnostic_test.cpp
        tests/file_reader_test.cpp
        tests/file_security_test.cpp
        tests/json_policy_test.cpp
        tests/path_policy_test.cpp
        tests/raw_run_receipt_test.cpp
        tests/report_writer_test.cpp
        tests/repository_audit_test.cpp
        tests/repository_validator_test.cpp
        tests/sha256_test.cpp
    )
    add_custom_target(rawframe_tool_rf_evidence_format_check ALL
        COMMAND "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}" --style=file --dry-run --Werror
            ${rawframe_tool_rf_evidence_maintained_sources}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Checking rf-evidence formatting against the repository .clang-format"
        VERBATIM)
endif()
