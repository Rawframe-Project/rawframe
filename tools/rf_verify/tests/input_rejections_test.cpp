#include "diff_reader.h"
#include "repository_paths.h"
#include "requirements.h"
#include "tier_declarations.h"
#include "tool_limits.h"
#include "verify_fixture.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace rawframe::tool::verify {

namespace {

Failure diffFailure(std::string_view bytes) {
    auto parsed = parseUnifiedDiff(bytes);
    EXPECT_FALSE(parsed.has_value()) << "the reader accepted a diff it cannot bound";
    if (parsed) {
        return Failure{FailureCode::MalformedDiff, {}, "accepted"};
    }
    return parsed.error();
}

std::string reportWith(std::string_view caseBody) {
    std::string document = R"({"testsuites":[{"name":"Suite","testsuite":[)";
    document += caseBody;
    document += "]}]}";
    return document;
}

Failure requirementsFailure(const testing::RepositoryFixture& fixture, std::string_view document) {
    fixture.write("out/report.json", document);
    auto report = buildRequirementsReport({}, {fixture.root() / "out/report.json"});
    EXPECT_FALSE(report.has_value()) << "the reader accepted a malformed test report";
    if (report) {
        return Failure{FailureCode::InvalidJson, {}, "accepted"};
    }
    return report.error();
}

Failure inventoryFailure(const testing::RepositoryFixture& fixture, std::string_view document) {
    fixture.write("out/criteria.json", document);
    auto read = readCriteriaInventory(fixture.root() / "out/criteria.json");
    EXPECT_FALSE(read.has_value()) << "the reader accepted a malformed criteria inventory";
    if (read) {
        return Failure{FailureCode::InvalidJson, {}, "accepted"};
    }
    return read.error();
}

} // namespace

TEST(DiffLimits, RefusesADiffLargerThanTheByteLimit) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const std::string kOversized(kMaximumDiffBytes + 1, ' ');
    EXPECT_EQ(diffFailure(kOversized).code, FailureCode::LimitExceeded);
}

TEST(DiffLimits, RefusesADiffNamingMoreFilesThanTheLimitAdmits) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    std::string document;
    document.reserve((kMaximumDiffFiles + 1) * 48);
    for (std::size_t index = 0; index <= kMaximumDiffFiles; ++index) {
        document += "+++ b/tools/subject/src/f" + std::to_string(index) + ".cpp\n";
        document += "@@ -0,0 +1 @@\n+a\n";
    }
    const Failure kFailure = diffFailure(document);
    EXPECT_EQ(kFailure.code, FailureCode::LimitExceeded);
    EXPECT_NE(kFailure.message.find("changed-file limit"), std::string::npos);
}

TEST(DiffLimits, RefusesOneFileCarryingMoreChangedLinesThanTheLimitAdmits) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    std::string document = "+++ b/tools/subject/src/parser.cpp\n@@ -0,0 +1 @@\n";
    document.reserve(document.size() + ((kMaximumChangedLinesPerFile + 2) * 3));
    for (std::size_t index = 0; index <= kMaximumChangedLinesPerFile; ++index) {
        document += "+a\n";
    }
    const Failure kFailure = diffFailure(document);
    EXPECT_EQ(kFailure.code, FailureCode::LimitExceeded);
    EXPECT_EQ(kFailure.path, "tools/subject/src/parser.cpp");
}

TEST(DiffLimits, AcceptsAHeaderWrittenWithTheOldSidePrefix) {
    auto parsed = parseUnifiedDiff("+++ a/tools/subject/src/parser.cpp\n@@ -0,0 +7 @@\n+a\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->files.size(), 1U);
    EXPECT_TRUE(parsed->files.at("tools/subject/src/parser.cpp").contains(7U));
}

TEST(DiffLimits, TrimsACarriageReturnBeforeReadingALine) {
    auto parsed = parseUnifiedDiff("+++ b/tools/subject/src/parser.cpp\r\n@@ -0,0 +3 @@\r\n+a\r\n");
    ASSERT_TRUE(parsed.has_value()) << parsed.error().message;
    ASSERT_EQ(parsed->files.size(), 1U);
    EXPECT_TRUE(parsed->files.at("tools/subject/src/parser.cpp").contains(3U));
}

TEST(DiffLimits, RefusesAHunkHeaderWithNoClosingMarker) {
    EXPECT_EQ(diffFailure("+++ b/x.cpp\n@@ -1,0 +1,1\n+a\n").code, FailureCode::MalformedDiff);
}

TEST(DiffLimits, ReportsAnIoFailureRatherThanAnEmptyChangeSet) {
    const testing::RepositoryFixture kFixture("diff_io_failure");
    // A directory opens as a path that exists and fails as a stream, which must
    // be a typed failure: an empty change set would read as a clean verdict.
    std::error_code code;
    std::filesystem::create_directories(kFixture.root() / "out/diffdir", code);
    auto read = readUnifiedDiff(kFixture.root() / "out/diffdir");
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::IoFailure);
}

TEST(RepositoryPathBoundary, RefusesAReportDestinationThatClimbsOutOfTheWriteRoot) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const testing::RepositoryFixture kFixture("paths_traversal");
    auto status = ensureWithinReportRoot(kFixture.root(), "out/reports/verify/../../escaped.json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidPath);
}

// A path the platform's canonicalizer refuses outright. Resolution is real
// filesystem work, and the shapes that defeat it differ by host: on Windows a
// reserved device name used as a directory, on POSIX a symbolic link that
// resolves through itself. Each host proves the rejection with the shape its own
// kernel produces, because a shape borrowed from the other host resolves
// harmlessly and would prove nothing.
namespace {

std::filesystem::path unresolvablePath([[maybe_unused]] const testing::RepositoryFixture& fixture) {
#ifdef _WIN32
    return std::filesystem::path("C:/nul/child");
#else
    std::error_code code;
    const auto kLoop = fixture.root() / "loop";
    std::filesystem::remove(kLoop, code);
    std::filesystem::create_symlink(kLoop, kLoop, code);
    return kLoop / "child";
#endif
}

} // namespace

TEST(RepositoryPathBoundary, RefusesEveryPathTheHostCannotResolveAtAll) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const testing::RepositoryFixture kFixture("paths_unresolvable");
    const auto kHostile = unresolvablePath(kFixture);

    auto root = resolveRepositoryRoot(kHostile);
    ASSERT_FALSE(root.has_value());
    EXPECT_EQ(root.error().code, FailureCode::InvalidPath);

    auto relative = repositoryRelative(kFixture.root(), kHostile.generic_string());
    ASSERT_FALSE(relative.has_value());
    EXPECT_EQ(relative.error().code, FailureCode::InvalidPath);

    auto destination = ensureWithinReportRoot(kFixture.root(), kHostile);
    ASSERT_FALSE(destination.has_value());
    EXPECT_EQ(destination.error().code, FailureCode::InvalidPath);
}

TEST(RepositoryPathBoundary, AdmitsAPublicHeaderAndRefusesATestOrGeneratedUnit) {
    EXPECT_TRUE(isMaintainedSourceUnit("source/base/include/rawframe/base/span.h"));
    EXPECT_TRUE(isMaintainedSourceUnit("tools/rf_verify/src/floors.cpp"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/tests/floors_test.cpp"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/floors.cpp"));
    EXPECT_FALSE(isMaintainedSourceUnit("out/build/generated/src/thing.cpp"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/src/notes.md"));
}

TEST(TierIndexRejections, RefusesAMembershipEntryThatIsNotAPath) {
    const testing::RepositoryFixture kFixture("tiers_entry_not_path");
    kFixture.writeIndex("[7]");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_EQ(index.error().code, FailureCode::InvalidJson);
    EXPECT_EQ(index.error().path, "repository.json");
}

TEST(TierIndexRejections, RefusesAMembershipEntryWithNoRoot) {
    const testing::RepositoryFixture kFixture("tiers_entry_no_root");
    kFixture.writeIndex(R"(["tool.json"])");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_NE(index.error().message.find("no root"), std::string::npos);
}

TEST(TierIndexRejections, RefusesAnIndexWithNoModuleArray) {
    const testing::RepositoryFixture kFixture("tiers_no_modules");
    kFixture.write("repository.json", "{\n  \"tools\": []\n}\n");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_EQ(index.error().code, FailureCode::InvalidJson);
}

TEST(TierIndexRejections, RefusesADeclarationWithNoUnitsArray) {
    const testing::RepositoryFixture kFixture("tiers_no_units");
    kFixture.write("tools/subject/tests/verification-tiers.json", "{\n  \"schemaVersion\": 1\n}\n");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_EQ(index.error().code, FailureCode::InvalidJson);
}

TEST(TierIndexRejections, RefusesAUnitDeclarationMissingAnyOfItsThreeFields) {
    const testing::RepositoryFixture kFixture("tiers_incomplete_unit");
    for (const std::string_view kUnits : {R"([{"tier":"A","reason":"r"}])",
                                          R"([{"path":"src/parser.cpp","reason":"r"}])",
                                          R"([{"path":"src/parser.cpp","tier":"A"}])",
                                          R"([{"path":7,"tier":"A","reason":"r"}])"}) {
        kFixture.writeTiers(kUnits);
        auto index = readTierIndex(kFixture.root());
        ASSERT_FALSE(index.has_value()) << kUnits;
        EXPECT_EQ(index.error().code, FailureCode::InvalidJson) << kUnits;
    }
}

TEST(TierIndexRejections, RefusesATierLetterTheStandardDoesNotDefine) {
    RecordProperty("requirement", "STD-0007:every-source-unit-carries-a-declared-tier");
    const testing::RepositoryFixture kFixture("tiers_unknown_letter");
    kFixture.writeTiers(R"([{"path":"src/parser.cpp","tier":"X","reason":"r"}])");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_NE(index.error().message.find("must be O, A, or H"), std::string::npos);
    EXPECT_NE(index.error().path.find("verification-tiers.json"), std::string::npos);
}

TEST(TierIndexRejections, RefusesTwoDeclarationsClaimingTheSameUnit) {
    const testing::RepositoryFixture kFixture("tiers_duplicate_unit");
    kFixture.writeTiers(R"([{"path":"src/parser.cpp","tier":"A","reason":"one"},)"
                        R"({"path":"src/parser.cpp","tier":"H","reason":"two"}])");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_NE(index.error().message.find("same source unit"), std::string::npos);
}

TEST(TierIndexRejections, RefusesADeclarationFileThatIsNotThere) {
    const testing::RepositoryFixture kFixture("tiers_absent_file");
    auto read = readTierDeclarationFile(kFixture.root() / "tools/subject/tests/absent.json", "tools/subject");
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::MissingInput);
}

TEST(TierIndexRejections, CollectsAPublicHeaderTreeAlongsideThePrivateOne) {
    const testing::RepositoryFixture kFixture("tiers_include_tree");
    kFixture.write("tools/subject/include/rawframe/subject/parser.h", "// declaration\n");
    auto index = readTierIndex(kFixture.root());
    ASSERT_TRUE(index.has_value()) << index.error().message;
    ASSERT_EQ(index->presentButUndeclared.size(), 1U);
    EXPECT_EQ(index->presentButUndeclared.front(), "tools/subject/include/rawframe/subject/parser.h");
}

TEST(RequirementsRejections, RefusesATestCaseEntryThatIsNotAnObject) {
    const testing::RepositoryFixture kFixture("requirements_case_not_object");
    EXPECT_EQ(requirementsFailure(kFixture, reportWith("7")).code, FailureCode::InvalidJson);
}

TEST(RequirementsRejections, RefusesARecordedRequirementThatIsNotAString) {
    const testing::RepositoryFixture kFixture("requirements_binding_not_string");
    const Failure kFailure =
        requirementsFailure(kFixture, reportWith(R"({"classname":"S","name":"t","requirement":7})"));
    EXPECT_EQ(kFailure.code, FailureCode::InvalidJson);
    EXPECT_NE(kFailure.path.find("report.json"), std::string::npos);
}

TEST(RequirementsRejections, RefusesABoundTestCaseWithNoName) {
    const testing::RepositoryFixture kFixture("requirements_case_no_name");
    EXPECT_EQ(requirementsFailure(kFixture, reportWith(R"({"name":"t","requirement":"A:one"})")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(requirementsFailure(kFixture, reportWith(R"({"classname":"S","requirement":"A:one"})")).code,
              FailureCode::InvalidJson);
}

TEST(RequirementsRejections, ReadsSeveralCriteriaFromOneBindingAndIgnoresTheEmptyParts) {
    RecordProperty("requirement", "STD-0007:requirements-report-is-generated-from-executed-tests");
    const testing::RepositoryFixture kFixture("requirements_split");
    kFixture.write("out/report.json",
                   reportWith(R"({"classname":"S","name":"t","requirement":" A:one ,\tA:two\t, ,"})"));
    std::vector<DeclaredCriterion> declared;
    declared.push_back(DeclaredCriterion{"A:one", "first", DischargeKind::Automated, {}, {}, {}});
    declared.push_back(DeclaredCriterion{"A:two", "second", DischargeKind::Automated, {}, {}, {}});
    auto report = buildRequirementsReport(declared, {kFixture.root() / "out/report.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->bindingsRead, 2U);
    EXPECT_EQ(report->bound.size(), 2U);
    EXPECT_TRUE(report->unbound.empty());
    EXPECT_TRUE(report->findings.empty());
}

TEST(RequirementsRejections, RefusesACriterionEntryMissingAnyOfItsRequiredFields) {
    const testing::RepositoryFixture kFixture("requirements_inventory_incomplete");
    for (const std::string_view kEntry : {R"({"text":"t","discharge":"automated"})",
                                          R"({"id":"A:one","discharge":"automated"})",
                                          R"({"id":"A:one","text":"t"})",
                                          R"({"id":7,"text":"t","discharge":"automated"})"}) {
        const std::string kDocument = R"({"criteria":[)" + std::string(kEntry) + "]}";
        EXPECT_EQ(inventoryFailure(kFixture, kDocument).code, FailureCode::InvalidJson) << kEntry;
    }
}

TEST(RequirementsRejections, RefusesACriterionIdentifierThatNamesNoDocument) {
    const testing::RepositoryFixture kFixture("requirements_inventory_id");
    const Failure kFailure =
        inventoryFailure(kFixture, R"({"criteria":[{"id":"one","text":"t","discharge":"automated"}]})");
    EXPECT_NE(kFailure.message.find("<DOC-ID>:<criterion>"), std::string::npos);
}

TEST(RequirementsRejections, RefusesAnInventoryDeclaringOneCriterionTwice) {
    const testing::RepositoryFixture kFixture("requirements_inventory_duplicate");
    const std::string kDocument = R"({"criteria":[{"id":"A:one","text":"t","discharge":"automated"},)"
                                  R"({"id":"A:one","text":"t","discharge":"automated"}]})";
    EXPECT_NE(inventoryFailure(kFixture, kDocument).message.find("twice"), std::string::npos);
}

TEST(RequirementsRejections, RefusesAManualCriterionThatNamesNoProcedure) {
    RecordProperty("requirement", "STD-0007:unbound-criteria-are-visible-and-counted");
    const testing::RepositoryFixture kFixture("requirements_inventory_manual");
    for (const std::string_view kEntry : {R"({"id":"A:one","text":"t","discharge":"manual"})",
                                          R"({"id":"A:one","text":"t","discharge":"manual","procedure":""})",
                                          R"({"id":"A:one","text":"t","discharge":"manual","procedure":7})"}) {
        const std::string kDocument = R"({"criteria":[)" + std::string(kEntry) + "]}";
        EXPECT_NE(inventoryFailure(kFixture, kDocument).message.find("name the procedure"), std::string::npos)
            << kEntry;
    }
}

TEST(RequirementsRejections, RefusesALaneCriterionThatNamesNothingThatDischargesIt) {
    RecordProperty("requirement", "STD-0007:unbound-criteria-are-visible-and-counted");
    const testing::RepositoryFixture kFixture("requirements_inventory_lane");
    for (const std::string_view kEntry : {R"({"id":"A:one","text":"t","discharge":"lane"})",
                                          R"({"id":"A:one","text":"t","discharge":"lane","dischargedBy":""})",
                                          R"({"id":"A:one","text":"t","discharge":"lane","dischargedBy":7})"}) {
        const std::string kDocument = R"({"criteria":[)" + std::string(kEntry) + "]}";
        EXPECT_NE(inventoryFailure(kFixture, kDocument).message.find("name what discharges it"), std::string::npos)
            << kEntry;
    }
}

TEST(RequirementsRejections, RefusesALaneCriterionWhoseNamedCasesAreNotNames) {
    const testing::RepositoryFixture kFixture("requirements_inventory_lane_cases");
    const std::string kPrefix = R"({"criteria":[{"id":"A:one","text":"t","discharge":"lane","dischargedBy":"d",)";
    EXPECT_NE(inventoryFailure(kFixture, kPrefix + R"("ctestCases":"Suite.One"}]})").message.find("must be an array"),
              std::string::npos);
    for (const std::string_view kCases : {R"([7])", R"([""])", R"(["ok", null])"}) {
        const std::string kDocument = kPrefix + R"("ctestCases":)" + std::string(kCases) + "}]}";
        EXPECT_NE(inventoryFailure(kFixture, kDocument).message.find("must each name one case"), std::string::npos)
            << kCases;
    }
}

TEST(RequirementsRejections, RefusesADischargeKindTheInventoryDoesNotDefine) {
    const testing::RepositoryFixture kFixture("requirements_inventory_discharge");
    const Failure kFailure =
        inventoryFailure(kFixture, R"({"criteria":[{"id":"A:one","text":"t","discharge":"reviewed"}]})");
    EXPECT_NE(kFailure.message.find("automated, manual, or lane"), std::string::npos);
}

TEST(RequirementsRejections, ReportsAManualCriterionSeparatelyFromAnUnboundOne) {
    RecordProperty("requirement", "STD-0007:unbound-criteria-are-visible-and-counted");
    const testing::RepositoryFixture kFixture("requirements_manual_report");
    kFixture.write("out/report.json", reportWith(R"({"classname":"S","name":"t"})"));
    std::vector<DeclaredCriterion> declared;
    declared.push_back(DeclaredCriterion{"A:one", "first", DischargeKind::Automated, {}, {}, {}});
    declared.push_back(DeclaredCriterion{"A:two", "second", DischargeKind::Manual, "read the report", {}, {}});
    auto report = buildRequirementsReport(declared, {kFixture.root() / "out/report.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->testsRead, 1U);
    EXPECT_EQ(report->bindingsRead, 0U);
    ASSERT_EQ(report->unbound.size(), 1U);
    EXPECT_EQ(report->unbound.front().id, "A:one");
    ASSERT_EQ(report->manual.size(), 1U);
    EXPECT_EQ(report->manual.front().procedure, "read the report");
}

TEST(TierIndexRejections, RefusesAnIndexThatCannotBeReadAtAll) {
    const testing::RepositoryFixture kFixture("tiers_no_index");
    kFixture.remove("repository.json");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_EQ(index.error().code, FailureCode::MissingInput);
}

TEST(TierIndexRejections, RefusesAMembershipArrayThatIsNotAnArray) {
    const testing::RepositoryFixture kFixture("tiers_membership_not_array");
    kFixture.write("repository.json", R"({"modules": [], "tools": 7})");
    auto index = readTierIndex(kFixture.root());
    ASSERT_FALSE(index.has_value());
    EXPECT_EQ(index.error().code, FailureCode::InvalidJson);
}

TEST(TierIndexRejections, WalksPastADirectoryInsideADeclaredSourceRoot) {
    const testing::RepositoryFixture kFixture("tiers_nested_directory");
    kFixture.write("tools/subject/src/nested/deeper.cpp", "int deeper() { return 0; }\n");
    auto index = readTierIndex(kFixture.root());
    ASSERT_TRUE(index.has_value()) << index.error().message;
    ASSERT_EQ(index->presentButUndeclared.size(), 1U);
    EXPECT_EQ(index->presentButUndeclared.front(), "tools/subject/src/nested/deeper.cpp");
}

TEST(TierIndexRejections, ReportsADeclarationForAUnitThatIsNotOnDisk) {
    const testing::RepositoryFixture kFixture("tiers_declared_absent");
    kFixture.writeTiers(R"([{"path": "src/parser.cpp", "tier": "A", "reason": "present"},)"
                        R"({"path": "src/gone.cpp", "tier": "O", "reason": "absent"}])");
    auto index = readTierIndex(kFixture.root());
    ASSERT_TRUE(index.has_value()) << index.error().message;
    ASSERT_EQ(index->declaredButAbsent.size(), 1U);
    EXPECT_EQ(index->declaredButAbsent.front(), "tools/subject/src/gone.cpp");
    EXPECT_TRUE(index->presentButUndeclared.empty());
}

TEST(RepositoryPathBoundary, NormalizesARootWhetherOrNotItAlreadyEndsInASeparator) {
    const testing::RepositoryFixture kFixture("paths_trailing_separator");
    const auto kUnit = kFixture.root() / "tools/subject/src/parser.cpp";

    auto plain = repositoryRelative(kFixture.root(), kUnit.generic_string());
    ASSERT_TRUE(plain.has_value()) << plain.error().message;
    EXPECT_EQ(*plain, "tools/subject/src/parser.cpp");

    auto trailing = repositoryRelative(kFixture.root().generic_string() + "/", kUnit.generic_string());
    ASSERT_TRUE(trailing.has_value()) << trailing.error().message;
    EXPECT_EQ(*trailing, "tools/subject/src/parser.cpp");

    // An empty root names no directory, so nothing can be inside it and the
    // whole reported path comes back unchanged rather than being cut short.
    auto empty = repositoryRelative(std::filesystem::path{}, "tools/subject/src/parser.cpp");
    ASSERT_TRUE(empty.has_value()) << empty.error().message;
    EXPECT_NE(empty->find("tools/subject/src/parser.cpp"), std::string::npos);
}

TEST(TierIndexRejections, RefusesAUnitsMemberThatIsNotAnArrayAndFieldsOfTheWrongType) {
    const testing::RepositoryFixture kFixture("tiers_units_types");
    kFixture.write("tools/subject/tests/verification-tiers.json", R"({"units": 7})");
    ASSERT_FALSE(readTierIndex(kFixture.root()).has_value());

    for (const std::string_view kUnits : {R"([{"path":"src/parser.cpp","tier":7,"reason":"r"}])",
                                          R"([{"path":"src/parser.cpp","tier":"A","reason":7}])"}) {
        kFixture.writeTiers(kUnits);
        auto index = readTierIndex(kFixture.root());
        ASSERT_FALSE(index.has_value()) << kUnits;
        EXPECT_EQ(index.error().code, FailureCode::InvalidJson) << kUnits;
    }
}

TEST(TierIndexRejections, WalksPastAFileInsideASourceRootThatIsNotASourceUnit) {
    const testing::RepositoryFixture kFixture("tiers_non_source_file");
    kFixture.write("tools/subject/src/notes.md", "not a translation unit\n");
    auto index = readTierIndex(kFixture.root());
    ASSERT_TRUE(index.has_value()) << index.error().message;
    EXPECT_TRUE(index->presentButUndeclared.empty());
    EXPECT_TRUE(index->declaredButAbsent.empty());
}

TEST(RequirementsRejections, RefusesAReportWhoseArraysAreNotArrays) {
    const testing::RepositoryFixture kFixture("requirements_not_arrays");
    EXPECT_EQ(requirementsFailure(kFixture, R"({"testsuites":7})").code, FailureCode::InvalidJson);
    EXPECT_EQ(requirementsFailure(kFixture, R"({})").code, FailureCode::InvalidJson);
}

TEST(RequirementsRejections, IgnoresASuiteWhoseCaseListIsNotAnArray) {
    const testing::RepositoryFixture kFixture("requirements_cases_not_array");
    kFixture.write("out/report.json", R"({"testsuites":[{"name":"S","testsuite":7}]})");
    auto report = buildRequirementsReport({}, {kFixture.root() / "out/report.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->testsRead, 0U);
}

TEST(RequirementsRejections, RefusesABoundTestCaseWhoseNameIsNotAString) {
    const testing::RepositoryFixture kFixture("requirements_name_types");
    EXPECT_EQ(requirementsFailure(kFixture, reportWith(R"({"classname":7,"name":"t","requirement":"A:one"})")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(requirementsFailure(kFixture, reportWith(R"({"classname":"S","name":7,"requirement":"A:one"})")).code,
              FailureCode::InvalidJson);
}

TEST(RequirementsRejections, RefusesATestReportThatIsNotThere) {
    const testing::RepositoryFixture kFixture("requirements_absent_report");
    auto report = buildRequirementsReport({}, {kFixture.root() / "out/absent.json"});
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::MissingInput);
}

TEST(RequirementsRejections, RefusesACriteriaMemberThatIsNotAnArrayAndFieldsOfTheWrongType) {
    const testing::RepositoryFixture kFixture("requirements_criteria_types");
    EXPECT_EQ(inventoryFailure(kFixture, R"({"criteria":7})").code, FailureCode::InvalidJson);
    EXPECT_EQ(inventoryFailure(kFixture, R"({})").code, FailureCode::InvalidJson);
    EXPECT_EQ(inventoryFailure(kFixture, R"({"criteria":[{"id":"A:one","text":7,"discharge":"automated"}]})").code,
              FailureCode::InvalidJson);
    EXPECT_EQ(inventoryFailure(kFixture, R"({"criteria":[{"id":"A:one","text":"t","discharge":7}]})").code,
              FailureCode::InvalidJson);
}

} // namespace rawframe::tool::verify
