// STD-0007's amendment of 2026-07-31: two branch shapes leave the denominator,
// and both are decided from the source bytes rather than from a declaration.
//
// The cases below are the two shapes, the two directions of each, and the
// boundary that keeps the classifier from swallowing an ordinary uncovered
// branch. The last of those is the one that matters: an exclusion that is too
// eager is indistinguishable from a lowered floor.

#include "coverage_exclusions.h"
#include "verify_fixture.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <string>
#include <string_view>
#include <system_error>

namespace rawframe::tool::verify {

namespace {

std::filesystem::path writeUnit(std::string_view name, std::string_view text) {
    const auto kRoot = testing::outputRoot() / "exclusions";
    std::error_code code;
    std::filesystem::create_directories(kRoot, code);
    const auto kPath = kRoot / (std::string(name) + ".cpp");
    std::ofstream stream(kPath, std::ios::binary | std::ios::trunc);
    stream.write(text.data(), static_cast<std::streamsize>(text.size()));
    return kPath;
}

BranchRegion regionAt(std::uint32_t line, std::uint32_t column, std::uint32_t endColumn) {
    BranchRegion region;
    region.line = line;
    region.column = column;
    region.endLine = line;
    region.endColumn = endColumn;
    return region;
}

} // namespace

TEST(CoverageExclusions, ExcludesTheConstantConditionOfTheSingleStatementMacroIdiom) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    // The exact idiom `assert.h` uses, continuation backslash included.
    const auto kPath = writeUnit("constant_condition",
                                 "#define RF_ASSERT(c) \\\n"
                                 "    do {              \\\n"
                                 "        use(c);       \\\n"
                                 "    } while (false)\n");
    auto unit = SourceUnit::read(kPath);
    ASSERT_TRUE(unit.has_value()) << unit.error().message;

    // Line 4, columns 14 through 19: the `false` between the parentheses.
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(4, 14, 19)), BranchExclusion::ConstantCondition);
}

TEST(CoverageExclusions, ExcludesAConstantConditionWrittenAsTrue) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    const auto kPath = writeUnit("constant_true", "void spin() {\n    while (true) { step(); }\n}\n");
    auto unit = SourceUnit::read(kPath);
    ASSERT_TRUE(unit.has_value()) << unit.error().message;
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(2, 12, 16)), BranchExclusion::ConstantCondition);
}

TEST(CoverageExclusions, ExcludesTheSynthesizedBodyOfADefaultedDeclaration) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    const auto kPath = writeUnit("defaulted",
                                 "struct Pair {\n"
                                 "    int high = 0;\n"
                                 "    friend constexpr bool operator==(const Pair&, const Pair&) noexcept = default;\n"
                                 "};\n");
    auto unit = SourceUnit::read(kPath);
    ASSERT_TRUE(unit.has_value()) << unit.error().message;

    // The region llvm-cov reports there is a single character inside a body the
    // source does not contain, so the column span is deliberately narrow.
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(3, 79, 80)), BranchExclusion::SynthesizedBody);
}

// The boundary. A branch that is merely uncovered, a condition that merely
// mentions a constant, and a line that merely contains the word `default` all
// stay in the denominator.
TEST(CoverageExclusions, KeepsAnOrdinaryConditionInTheDenominator) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    const auto kPath = writeUnit("ordinary",
                                 "int classify(int value) {\n"
                                 "    if (value == 0) { return 1; }\n"
                                 "    if (value == false) { return 2; }\n"
                                 "    switch (value) { default: return 3; }\n"
                                 "}\n");
    auto unit = SourceUnit::read(kPath);
    ASSERT_TRUE(unit.has_value()) << unit.error().message;

    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(2, 9, 19)), BranchExclusion::None);
    // `value == false` names a constant and is still a real decision.
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(3, 9, 23)), BranchExclusion::None);
    // A `default:` label is not a defaulted declaration.
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(4, 9, 19)), BranchExclusion::None);
}

// A span the source cannot answer produces no exclusion rather than a guess. A
// region that reaches past the line, one that crosses lines, and one with no
// column at all are all cases where reading the text would mean reading
// something else.
TEST(CoverageExclusions, KeepsARegionItCannotReadInTheDenominator) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    const auto kPath = writeUnit("unreadable", "void run() {\n    while (false) {}\n}\n");
    auto unit = SourceUnit::read(kPath);
    ASSERT_TRUE(unit.has_value()) << unit.error().message;

    BranchRegion acrossLines = regionAt(2, 12, 17);
    acrossLines.endLine = 3;
    EXPECT_EQ(classifyBranchRegion(*unit, acrossLines), BranchExclusion::None);
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(2, 12, 400)), BranchExclusion::None);
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(2, 0, 5)), BranchExclusion::None);
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(900, 1, 5)), BranchExclusion::None);
    // An inverted span reads no text either.
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(2, 17, 12)), BranchExclusion::None);
    // And the readable one still classifies, so the case is not passing because
    // the fixture was unreadable in every direction.
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(2, 12, 17)), BranchExclusion::ConstantCondition);
}

TEST(CoverageExclusions, RefusesASourceUnitItCannotRead) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    auto missing = SourceUnit::read(testing::outputRoot() / "exclusions" / "there-is-no-such-unit.cpp");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, FailureCode::MissingInput);
}

TEST(CoverageExclusions, NamesEveryExclusionReason) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    EXPECT_EQ(branchExclusionName(BranchExclusion::None), "none");
    EXPECT_EQ(branchExclusionName(BranchExclusion::ConstantCondition), "constant_condition");
    EXPECT_EQ(branchExclusionName(BranchExclusion::SynthesizedBody), "synthesized_body");
}

// An empty unit is a real input: a header that only declares can end up here,
// and reading past the end of nothing is how a classifier crashes rather than
// reports.
TEST(CoverageExclusions, ReadsAnEmptyUnitWithoutReachingPastIt) {
    RecordProperty("requirement", "STD-0007:the-denominator-excludes-only-mechanical-shapes");

    const auto kPath = writeUnit("empty", "");
    auto unit = SourceUnit::read(kPath);
    ASSERT_TRUE(unit.has_value()) << unit.error().message;
    EXPECT_TRUE(unit->line(1).empty());
    EXPECT_EQ(classifyBranchRegion(*unit, regionAt(1, 1, 5)), BranchExclusion::None);
}

} // namespace rawframe::tool::verify
