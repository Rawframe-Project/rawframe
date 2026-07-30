add_executable(rawframe_tool_rf_evidence_tests
    attestation_test.cpp
    baseline_record_test.cpp
    blob_store_test.cpp
    canonical_json_test.cpp
    command_test.cpp
    closure_conformance_test.cpp
    conformance_test.cpp
    dependency_authority_test.cpp
    descriptor_test.cpp
    diagnostic_test.cpp
    evaluation_policy_test.cpp
    evaluator_test.cpp
    evidence_set_test.cpp
    file_reader_test.cpp
    file_security_test.cpp
    json_policy_test.cpp
    license_review_test.cpp
    metric_registry_test.cpp
    offline_verifier_test.cpp
    path_audit_test.cpp
    path_policy_test.cpp
    process_runner_test.cpp
    raw_run_receipt_test.cpp
    record_gate_test.cpp
    report_writer_test.cpp
    repository_audit_test.cpp
    repository_validator_test.cpp
    schema_oracle_test.cpp
    sha256_test.cpp
    shipping_closure_test.cpp
    source_inspector_test.cpp
    trust_policy_test.cpp
)
target_link_libraries(rawframe_tool_rf_evidence_tests PRIVATE
    rawframe_tool_rf_evidence_private
    GTest::gtest_main
)
target_compile_definitions(rawframe_tool_rf_evidence_tests PRIVATE
    RAWFRAME_TEST_REPOSITORY_ROOT="${CMAKE_SOURCE_DIR}"
    RAWFRAME_TEST_OUTPUT_ROOT="${CMAKE_BINARY_DIR}/test_output"
    # The host whose prepared tools this configuration was built against, so the
    # attestation test can name the locked verifier the offline lane prepares
    # rather than search for one.
    RAWFRAME_TEST_HOST_ID="${RAWFRAME_HOST_ID}"
    # The locked CMake is the admitted interpreter and is already required to
    # configure this tree, so process tests drive it as their child rather than
    # acquiring or assuming any other executable.
    RAWFRAME_TEST_CMAKE_COMMAND="${CMAKE_COMMAND}"
)

include(GoogleTest)
gtest_discover_tests(rawframe_tool_rf_evidence_tests
    DISCOVERY_TIMEOUT 15
    PROPERTIES TIMEOUT 15
)
