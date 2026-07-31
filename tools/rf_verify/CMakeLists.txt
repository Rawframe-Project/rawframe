find_package(simdjson 4.6.4 CONFIG REQUIRED)

add_library(rawframe_tool_rf_verify_private STATIC)
target_sources(rawframe_tool_rf_verify_private PRIVATE
    src/command.cpp
    src/coverage_export.cpp
    src/coverage_summary.cpp
    src/diff_reader.cpp
    src/floors.cpp
    src/json_reader.cpp
    src/report_writer.cpp
    src/repository_paths.cpp
    src/requirements.cpp
    src/tier_declarations.cpp
)
target_include_directories(rawframe_tool_rf_verify_private PUBLIC src)
target_link_libraries(rawframe_tool_rf_verify_private PUBLIC
    rawframe::compiler_policy
    simdjson::simdjson
)
set_target_properties(rawframe_tool_rf_verify_private PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

add_executable(rawframe_tool_rf_verify src/main.cpp)
target_link_libraries(rawframe_tool_rf_verify PRIVATE rawframe_tool_rf_verify_private)
set_target_properties(rawframe_tool_rf_verify PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    OUTPUT_NAME rf-verify
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tools"
)

if(RAWFRAME_BUILD_TESTS)
    find_package(GTest 1.17.0 EXACT CONFIG REQUIRED)
    add_subdirectory(tests)
endif()

if(RAWFRAME_ENABLE_ANALYSIS)
    if(NOT DEFINED RAWFRAME_CLANG_FORMAT_EXECUTABLE OR
       NOT EXISTS "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}")
        message(FATAL_ERROR "RF1121 the preset's locked clang-format executable is absent")
    endif()
    set(rawframe_tool_rf_verify_maintained_sources
        src/command.cpp
        src/command.h
        src/coverage_export.cpp
        src/coverage_export.h
        src/coverage_summary.cpp
        src/coverage_summary.h
        src/diff_reader.cpp
        src/diff_reader.h
        src/failure.h
        src/findings.h
        src/floors.cpp
        src/floors.h
        src/json_reader.cpp
        src/json_reader.h
        src/main.cpp
        src/report_writer.cpp
        src/report_writer.h
        src/repository_paths.cpp
        src/repository_paths.h
        src/requirements.cpp
        src/requirements.h
        src/tier_declarations.cpp
        src/tier_declarations.h
        src/tool_limits.h
        tests/command_test.cpp
        tests/coverage_export_rejections_test.cpp
        tests/coverage_export_test.cpp
        tests/diff_reader_test.cpp
        tests/floors_test.cpp
        tests/input_rejections_test.cpp
        tests/json_reader_test.cpp
        tests/report_writer_test.cpp
        tests/repository_paths_test.cpp
        tests/requirements_test.cpp
        tests/verify_fixture.h
    )
    add_custom_target(rawframe_tool_rf_verify_format_check ALL
        COMMAND "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}" --style=file --dry-run --Werror
            ${rawframe_tool_rf_verify_maintained_sources}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Checking rf-verify formatting against the repository .clang-format"
        VERBATIM)
endif()
