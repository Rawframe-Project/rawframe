add_executable(rawframe_base_tests
    allocation_observer.cpp
    assert_test.cpp
    assertion_side_effect_lint_test.cpp
    bits128_test.cpp
    bytes_test.cpp
    fatal_test.cpp
    public_surface_test.cpp
)
target_link_libraries(rawframe_base_tests PRIVATE
    rawframe::base
    GTest::gmock
    GTest::gtest_main
)
# The public-surface scan reads the maintained headers, because the headers are
# the surface it enumerates, and the side-effect lint reads the production tree
# above this one. Nothing else in the module reads a path.
target_compile_definitions(rawframe_base_tests PRIVATE
    RAWFRAME_BASE_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/.."
)
set_target_properties(rawframe_base_tests PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

include(GoogleTest)
gtest_discover_tests(rawframe_base_tests
    DISCOVERY_TIMEOUT 15
    PROPERTIES TIMEOUT 30
)

# SPEC-0046 conformance item 2. One translation unit per public header, each
# including that header and nothing else. Building is the whole of the test: a
# header that reached for another module or for a companion include would not
# compile here.
add_library(rawframe_base_single_header_probe STATIC
    single_header/assert_alone.cpp
    single_header/bits128_alone.cpp
    single_header/bytes_alone.cpp
    single_header/fatal_alone.cpp
    single_header/platform_alone.cpp
)
target_link_libraries(rawframe_base_single_header_probe PRIVATE rawframe::base)
set_target_properties(rawframe_base_single_header_probe PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

# SPEC-0046 conformance item 3. An executable that links base and nothing else,
# and runs. A link-time dependency is invisible to a header check, so this is the
# only place the closure claim can be made.
add_executable(rawframe_base_link_probe link_probe.cpp)
target_link_libraries(rawframe_base_link_probe PRIVATE rawframe::base)
set_target_properties(rawframe_base_link_probe PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)
add_test(NAME "Base.LinksAndRunsWithoutAnyOtherModule"
    COMMAND "$<TARGET_FILE:rawframe_base_link_probe>")
set_tests_properties("Base.LinksAndRunsWithoutAnyOtherModule" PROPERTIES
    PASS_REGULAR_EXPRESSION "rawframe.base links and runs alone"
    LABELS "architecture" TIMEOUT 60)

# The three fixtures that must not compile. Each is excluded from the default
# build and is built on demand by its own CTest case, which passes on the exact
# diagnostic rather than on any failure: a fixture that failed for an unrelated
# reason would otherwise report the rule as proved.
foreach(negative_case IN ITEMS
        "unsupported_compiler|Rawframe requires a pinned Clang or MSVC frontend"
        "unsupported_architecture|Rawframe supports only the x86-64 architecture"
        "shipping_assertion_names_nothing|theIdentifierThisAssertionNamesDoesNotExist")
    string(REPLACE "|" ";" negative_fields "${negative_case}")
    list(GET negative_fields 0 negative_name)
    list(GET negative_fields 1 negative_diagnostic)

    add_executable(rawframe_base_negative_${negative_name} EXCLUDE_FROM_ALL
        negative/${negative_name}.cpp)
    target_link_libraries(rawframe_base_negative_${negative_name} PRIVATE rawframe::base)
    set_target_properties(rawframe_base_negative_${negative_name} PROPERTIES
        CXX_STANDARD 23
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
    )

    add_test(NAME "Base.NegativeCompile.${negative_name}"
        COMMAND "${CMAKE_COMMAND}" --build "${CMAKE_BINARY_DIR}"
            --target rawframe_base_negative_${negative_name})
    set_tests_properties("Base.NegativeCompile.${negative_name}" PROPERTIES
        PASS_REGULAR_EXPRESSION "${negative_diagnostic}"
        LABELS "architecture;build" TIMEOUT 300)
endforeach()
