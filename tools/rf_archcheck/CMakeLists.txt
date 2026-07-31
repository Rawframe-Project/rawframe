find_package(simdjson 4.6.4 CONFIG REQUIRED)

add_library(rawframe_tool_rf_archcheck_private STATIC)
target_sources(rawframe_tool_rf_archcheck_private PRIVATE
    src/checks_closure.cpp
    src/checks_edges.cpp
    src/checks_manifest.cpp
    src/checks_membership.cpp
    src/checks_projection.cpp
    src/checks_separation.cpp
    src/checks_source.cpp
    src/command.cpp
    src/engine.cpp
    src/findings.cpp
    src/json_reader.cpp
    src/repository_model.cpp
    src/repository_scan.cpp
    src/rule_corpus.cpp
    src/text_scan.cpp
)
target_include_directories(rawframe_tool_rf_archcheck_private PUBLIC src)
target_link_libraries(rawframe_tool_rf_archcheck_private PUBLIC
    rawframe::compiler_policy
    simdjson::simdjson
)
set_target_properties(rawframe_tool_rf_archcheck_private PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

add_executable(rawframe_tool_rf_archcheck src/main.cpp)
target_link_libraries(rawframe_tool_rf_archcheck PRIVATE rawframe_tool_rf_archcheck_private)
set_target_properties(rawframe_tool_rf_archcheck PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    OUTPUT_NAME rf-archcheck
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
    set(rawframe_tool_rf_archcheck_maintained_sources
        src/checks.h
        src/checks_closure.cpp
        src/checks_edges.cpp
        src/checks_manifest.cpp
        src/checks_membership.cpp
        src/checks_projection.cpp
        src/checks_separation.cpp
        src/checks_source.cpp
        src/command.cpp
        src/command.h
        src/engine.cpp
        src/engine.h
        src/failure.h
        src/findings.cpp
        src/findings.h
        src/json_reader.cpp
        src/json_reader.h
        src/tool_limits.h
        src/main.cpp
        src/repository_model.cpp
        src/repository_model.h
        src/repository_scan.cpp
        src/repository_scan.h
        src/rule_corpus.cpp
        src/rule_corpus.h
        src/text_scan.cpp
        src/text_scan.h
        tests/checks_test.cpp
        tests/command_test.cpp
        tests/conformance_test.cpp
        tests/corpus_test.cpp
        tests/json_reader_test.cpp
        tests/repository_scan_test.cpp
    )
    add_custom_target(rawframe_tool_rf_archcheck_format_check ALL
        COMMAND "${RAWFRAME_CLANG_FORMAT_EXECUTABLE}" --style=file --dry-run --Werror
            ${rawframe_tool_rf_archcheck_maintained_sources}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMENT "Checking rf-archcheck formatting against the repository .clang-format"
        VERBATIM)
endif()
