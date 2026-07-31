add_executable(rawframe_tool_rf_archcheck_tests
    checks_test.cpp
    command_test.cpp
    conformance_test.cpp
    corpus_test.cpp
    json_reader_test.cpp
    repository_scan_test.cpp
)
target_link_libraries(rawframe_tool_rf_archcheck_tests PRIVATE
    rawframe_tool_rf_archcheck_private
    GTest::gtest_main
)
target_compile_definitions(rawframe_tool_rf_archcheck_tests PRIVATE
    RAWFRAME_TEST_REPOSITORY_ROOT="${CMAKE_SOURCE_DIR}"
    RAWFRAME_TEST_OUTPUT_ROOT="${CMAKE_BINARY_DIR}/test_output"
    RAWFRAME_TEST_FIXTURE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
)
set_target_properties(rawframe_tool_rf_archcheck_tests PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

include(GoogleTest)
gtest_discover_tests(rawframe_tool_rf_archcheck_tests
    DISCOVERY_TIMEOUT 15
    PROPERTIES TIMEOUT 15
)
