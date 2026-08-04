add_executable(rawframe_tool_rf_verify_tests
    command_test.cpp
    coverage_exclusions_test.cpp
    coverage_export_rejections_test.cpp
    coverage_export_test.cpp
    diff_reader_test.cpp
    floors_test.cpp
    input_rejections_test.cpp
    json_reader_test.cpp
    report_writer_test.cpp
    repository_paths_test.cpp
    requirements_test.cpp
)
target_link_libraries(rawframe_tool_rf_verify_tests PRIVATE
    rawframe_tool_rf_verify_private
    GTest::gtest_main
)
target_compile_definitions(rawframe_tool_rf_verify_tests PRIVATE
    RAWFRAME_TEST_REPOSITORY_ROOT="${CMAKE_SOURCE_DIR}"
    RAWFRAME_TEST_OUTPUT_ROOT="${CMAKE_BINARY_DIR}/test_output"
)
set_target_properties(rawframe_tool_rf_verify_tests PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

include(GoogleTest)
# Every case builds its scratch repository beneath one shared output root, and
# the repository-level requirements test runs this same executable again to
# produce a real GoogleTest report. The lock keeps the two out of each other's
# scratch tree rather than making the fixtures carry unique names nobody would
# maintain.
gtest_discover_tests(rawframe_tool_rf_verify_tests
    DISCOVERY_TIMEOUT 15
    PROPERTIES TIMEOUT 15 RESOURCE_LOCK "rawframe_rf_verify_scratch"
)
