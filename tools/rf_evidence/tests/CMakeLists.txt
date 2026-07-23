add_executable(rawframe_tool_rf_evidence_tests
    command_test.cpp
    json_policy_test.cpp
    path_policy_test.cpp
    report_writer_test.cpp
    repository_audit_test.cpp
    repository_validator_test.cpp
    sha256_test.cpp
)
target_link_libraries(rawframe_tool_rf_evidence_tests PRIVATE
    rawframe_tool_rf_evidence_private
    GTest::gtest_main
)
target_compile_definitions(rawframe_tool_rf_evidence_tests PRIVATE
    RAWFRAME_TEST_REPOSITORY_ROOT="${CMAKE_SOURCE_DIR}"
    RAWFRAME_TEST_OUTPUT_ROOT="${CMAKE_BINARY_DIR}/test_output"
)

include(GoogleTest)
gtest_discover_tests(rawframe_tool_rf_evidence_tests
    DISCOVERY_TIMEOUT 15
    PROPERTIES TIMEOUT 15
)
