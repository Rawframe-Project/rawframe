#include "coverage_export.h"
#include "coverage_summary.h"
#include "failure.h"
#include "json_reader.h"
#include "report_writer.h"
#include "tier_declarations.h"
#include "tool_limits.h"
#include "verify_fixture.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <sstream>
#include <string>

namespace rawframe::tool::verify {

namespace {

std::string writtenBy(void (*body)(JsonWriter&)) {
    std::ostringstream output;
    JsonWriter writer(output);
    body(writer);
    return output.str();
}

} // namespace

TEST(FailureVocabulary, NamesEveryCodeDistinctlyAndMapsOnlyMisuseToUsage) {
    constexpr std::array kCodes{FailureCode::InvalidArguments,
                                FailureCode::InvalidJson,
                                FailureCode::InvalidPath,
                                FailureCode::IoFailure,
                                FailureCode::LimitExceeded,
                                FailureCode::MalformedDiff,
                                FailureCode::MissingInput,
                                FailureCode::NoChangedLines,
                                FailureCode::UncoveredChangedFile};
    constexpr std::array kNames{"invalid_arguments",
                                "invalid_json",
                                "invalid_path",
                                "io_failure",
                                "limit_exceeded",
                                "malformed_diff",
                                "missing_input",
                                "no_changed_lines",
                                "uncovered_changed_file"};
    static_assert(kCodes.size() == kNames.size());
    for (std::size_t index = 0; index < kCodes.size(); ++index) {
        EXPECT_STREQ(failureCodeName(kCodes.at(index)), kNames.at(index));
        EXPECT_EQ(isUsageFailure(kCodes.at(index)), kCodes.at(index) == FailureCode::InvalidArguments);
    }
}

TEST(VerificationTiers, NamesAndFloorsEveryTierTheStandardDefines) {
    RecordProperty("requirement", "STD-0007:no-change-lands-below-its-tier-floor");
    EXPECT_EQ(tierName(VerificationTier::Ordinary), "O");
    EXPECT_EQ(tierName(VerificationTier::Authority), "A");
    EXPECT_EQ(tierName(VerificationTier::Hostile), "H");
    EXPECT_EQ(tierBranchFloorPercent(VerificationTier::Ordinary), 80);
    EXPECT_EQ(tierBranchFloorPercent(VerificationTier::Authority), 90);
    EXPECT_EQ(tierBranchFloorPercent(VerificationTier::Hostile), 100);
}

TEST(ReportWriter, EscapesEveryCharacterJsonCannotCarryLiterally) {
    const std::string kWritten = writtenBy([](JsonWriter& writer) {
        writer.writeString(std::string("q\"b\\s\nn\rr\tt\x01u", 12));
    });
    EXPECT_EQ(kWritten, R"("q\"b\\s\nn\rr\tt\u0001")");
}

TEST(ReportWriter, SeparatesMembersAndElementsAtEveryDepth) {
    const std::string kWritten = writtenBy([](JsonWriter& writer) {
        writer.beginObject();
        writer.member("first", std::string_view{"one"});
        writer.member("second", std::int64_t{2});
        writer.member("third", true);
        writer.key("empty");
        writer.beginArray();
        writer.endArray();
        writer.key("nested");
        writer.beginArray();
        writer.beginObject();
        writer.member("inner", false);
        writer.endObject();
        writer.beginObject();
        writer.endObject();
        writer.endArray();
        writer.endObject();
    });
    const std::string kExpected = "{\n"
                                  "  \"first\": \"one\",\n"
                                  "  \"second\": 2,\n"
                                  "  \"third\": true,\n"
                                  "  \"empty\": [],\n"
                                  "  \"nested\": [\n"
                                  "    {\n"
                                  "      \"inner\": false\n"
                                  "    },\n"
                                  "    {}\n"
                                  "  ]\n"
                                  "}";
    EXPECT_EQ(kWritten, kExpected);
}

TEST(ReportWriter, WritesTheTypedArrayHelpers) {
    const std::string kWritten = writtenBy([](JsonWriter& writer) {
        writer.beginObject();
        writer.key("names");
        writer.writeStringArray({"a", "b"});
        writer.key("lines");
        writer.writeIntegerArray({3U, 4U});
        writer.endObject();
    });
    EXPECT_NE(kWritten.find(R"("a",)"), std::string::npos);
    EXPECT_NE(kWritten.find("3,"), std::string::npos);
}

TEST(ReportWriter, WritesBeneathTheDeclaredRootByAbsoluteOrRelativeDestination) {
    const testing::RepositoryFixture kFixture("writer_destinations");
    ASSERT_TRUE(writeReportFile(kFixture.root(), "out/reports/verify/relative.json", "{}\n").has_value());
    EXPECT_TRUE(std::filesystem::exists(kFixture.root() / "out/reports/verify/relative.json"));

    const auto kAbsolute = kFixture.root() / "out/reports/verify/nested/absolute.json";
    ASSERT_TRUE(writeReportFile(kFixture.root(), kAbsolute, "{}\n").has_value());
    EXPECT_TRUE(std::filesystem::exists(kAbsolute));
}

TEST(ReportWriter, RefusesADestinationOutsideTheDeclaredRoot) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const testing::RepositoryFixture kFixture("writer_outside");
    auto status = writeReportFile(kFixture.root(), "out/reports/elsewhere.json", "{}\n");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidPath);
    EXPECT_FALSE(std::filesystem::exists(kFixture.root() / "out/reports/elsewhere.json"));
}

TEST(ReportWriter, ReportsAnIoFailureRatherThanASilentlyMissingReport) {
    const testing::RepositoryFixture kFixture("writer_io_failure");
    // A regular file where a directory has to be: `create_directories` fails and
    // the report never appears, which must be a typed failure rather than a run
    // that reports success and writes nothing.
    kFixture.write("out/reports/verify/occupied", "not a directory\n");
    auto blocked = writeReportFile(kFixture.root(), "out/reports/verify/occupied/report.json", "{}\n");
    ASSERT_FALSE(blocked.has_value());
    EXPECT_EQ(blocked.error().code, FailureCode::IoFailure);

    // A directory where the report itself has to be: the open fails instead.
    std::error_code code;
    std::filesystem::create_directories(kFixture.root() / "out/reports/verify/occupied_directory", code);
    auto unopenable = writeReportFile(kFixture.root(), "out/reports/verify/occupied_directory", "{}\n");
    ASSERT_FALSE(unopenable.has_value());
    EXPECT_EQ(unopenable.error().code, FailureCode::IoFailure);
}

TEST(JsonNumbers, ReadsALiteralWhateverStructuralCharacterFollowsIt) {
    for (const std::string_view kDocument :
         {R"({"a":12})", R"({"a":12 })", R"([12])", R"([12,3])", R"([12 ])", "[12\n]", "[12\t]", "[12\r\n]"}) {
        auto parsed = parseJson(kDocument);
        ASSERT_TRUE(parsed.has_value()) << kDocument;
        const JsonNode* node = parsed->isObject() ? parsed->find("a") : &parsed->elements.front();
        ASSERT_NE(node, nullptr);
        auto value = readInteger(*node);
        ASSERT_TRUE(value.has_value()) << kDocument << ": " << value.error().message;
        EXPECT_EQ(*value, 12) << kDocument;
    }
}

TEST(JsonNumbers, RefusesADocumentLargerThanTheByteLimit) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const std::string kOversized(kMaximumJsonBytes + 1, ' ');
    auto parsed = parseJson(kOversized);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error().code, FailureCode::LimitExceeded);
}

TEST(JsonNumbers, RefusesAFileLargerThanTheByteLimitWithoutReadingIt) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const testing::RepositoryFixture kFixture("json_byte_limit");
    const auto kPath = kFixture.root() / "out/big.json";
    std::error_code code;
    std::filesystem::create_directories(kPath.parent_path(), code);
    // The reader consults the size before it loads anything, so the file is
    // extended rather than written: no test needs to push a quarter of a
    // gigabyte through a stream to prove the ceiling holds.
    {
        const std::ofstream kStream(kPath, std::ios::binary | std::ios::trunc);
    }
    std::filesystem::resize_file(kPath, kMaximumJsonBytes + 1, code);
    ASSERT_FALSE(code) << code.message();
    ASSERT_GT(std::filesystem::file_size(kPath, code), kMaximumJsonBytes);
    auto read = readJsonFile(kPath);
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::LimitExceeded);
    std::filesystem::remove(kPath, code);
}

TEST(CoverageSummaryReporting, StopsListingUncoveredLinesAtTheCapAndSaysHowManyItOmitted) {
    RecordProperty("requirement", "STD-0007:the-uncovered-set-is-the-review-artifact");
    CoverageExport coverage;
    CoverageFile file;
    file.path = "tools/subject/src/parser.cpp";
    for (std::uint32_t line = 1; line <= kMaximumReportedUncoveredLines + 7; ++line) {
        file.lineCounts.emplace(line, 0);
    }
    file.lineCounts.emplace(kMaximumReportedUncoveredLines + 100, 3);
    coverage.files.emplace(file.path, std::move(file));

    TierIndex tiers;
    auto summary = summarizeCoverage(coverage, tiers);
    ASSERT_TRUE(summary.has_value()) << summary.error().message;
    ASSERT_EQ(summary->files.size(), 1U);
    EXPECT_EQ(summary->files.front().uncoveredLines.size(), kMaximumReportedUncoveredLines);
    EXPECT_EQ(summary->omittedUncoveredLines, 7U);
    EXPECT_TRUE(summary->files.front().tier.empty());
}

TEST(CoverageSummaryReporting, LeavesAFullyCoveredBranchAndACoveredDecisionOutOfTheUncoveredSet) {
    CoverageExport coverage;
    CoverageFile file;
    file.path = "tools/subject/src/parser.cpp";
    file.branches.push_back(BranchRegion{.line = 4, .column = 1, .trueCount = 1, .falseCount = 1});
    file.branches.push_back(BranchRegion{.line = 5, .column = 1, .trueCount = 1, .falseCount = 0});

    McdcDecision covered;
    covered.line = 9;
    covered.conditionCount = 1;
    covered.vectors.push_back(McdcTestVector{{McdcTestVector::ConditionValue::True}, true, true});
    covered.vectors.push_back(McdcTestVector{{McdcTestVector::ConditionValue::False}, true, false});
    file.decisions.push_back(std::move(covered));
    coverage.files.emplace(file.path, std::move(file));

    TierIndex tiers;
    TierDeclaration declaration;
    declaration.path = "tools/subject/src/parser.cpp";
    declaration.tier = VerificationTier::Hostile;
    tiers.units.emplace(declaration.path, declaration);

    auto summary = summarizeCoverage(coverage, tiers);
    ASSERT_TRUE(summary.has_value()) << summary.error().message;
    ASSERT_EQ(summary->files.size(), 1U);
    EXPECT_EQ(summary->files.front().tier, "H");
    ASSERT_EQ(summary->files.front().partiallyCoveredBranchLines.size(), 1U);
    EXPECT_EQ(summary->files.front().partiallyCoveredBranchLines.front(), 5U);
    EXPECT_TRUE(summary->files.front().uncoveredDecisionLines.empty());
}

} // namespace rawframe::tool::verify
