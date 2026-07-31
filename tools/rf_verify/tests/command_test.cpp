#include "command.h"
#include "findings.h"
#include "tier_declarations.h"
#include "verify_fixture.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::verify {

namespace {

struct Run {
    int exitCode = 0;
    std::string output;
    std::string errors;
};

Run invoke(const std::vector<std::string>& arguments) {
    std::vector<std::string_view> views;
    views.reserve(arguments.size());
    for (const auto& argument : arguments) {
        views.emplace_back(argument);
    }
    std::ostringstream output;
    std::ostringstream errors;
    Run run;
    run.exitCode = runCommand(views, output, errors);
    run.output = output.str();
    run.errors = errors.str();
    return run;
}

bool contains(std::string_view haystack, std::string_view needle) {
    return haystack.contains(needle);
}

// Ten branch regions on lines one through ten, the first `covered` of them on
// both outcomes. The measured percentage is therefore exactly `covered * 10`.
std::string branchesWith(int covered) {
    std::string document = "[";
    for (int index = 0; index < 10; ++index) {
        const int kCount = index < covered ? 1 : 0;
        document += "[" + std::to_string(index + 1) + ",1," + std::to_string(index + 1) + ",5," +
                    std::to_string(kCount) + "," + std::to_string(kCount) + ",0,0,6]";
        document += index == 9 ? "" : ",";
    }
    return document + "]";
}

} // namespace

TEST(Command, RefusesAnInvocationItDoesNotUnderstand) {
    EXPECT_EQ(invoke({}).exitCode, kExitUsage);
    EXPECT_EQ(invoke({"measure_everything"}).exitCode, kExitUsage);
    EXPECT_EQ(invoke({"coverage_summary", "--unknown", "value"}).exitCode, kExitUsage);
    EXPECT_EQ(invoke({"coverage_summary", "--export"}).exitCode, kExitUsage);
    EXPECT_EQ(invoke({"coverage_summary"}).exitCode, kExitUsage);
    EXPECT_EQ(invoke({"coverage_floors", "--export", "e.json"}).exitCode, kExitUsage);
    EXPECT_EQ(invoke({"requirements_report"}).exitCode, kExitUsage);
}

TEST(Command, RefusesARootThatIsNotThisRepository) {
    const testing::RepositoryFixture kFixture("command_bad_root");
    kFixture.remove("repository.json");
    const auto kRun = invoke({"coverage_summary", "--root", kFixture.root().string(), "--export", "absent.json"});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "missing_input"));
}

TEST(Command, PassesAChangeAboveItsFloorAndFailsTheSameChangeBelowIt) {
    RecordProperty("requirement", "STD-0007:no-change-lands-below-its-tier-floor");
    const testing::RepositoryFixture kFixture("command_floors");
    const auto kDiff = kFixture.writeDiff(testing::diffAddingSubjectLines(1, 10));

    kFixture.writeExport(branchesWith(9));
    const auto kAbove = invoke({"coverage_floors",
                                "--root",
                                kFixture.root().string(),
                                "--export",
                                (kFixture.root() / "out/coverage/export.json").string(),
                                "--diff",
                                kDiff.string()});
    EXPECT_EQ(kAbove.exitCode, kExitConformant);
    EXPECT_TRUE(contains(kAbove.output, "\"findingCount\": 0"));
    EXPECT_TRUE(contains(kAbove.output, "\"meetsFloor\": true"));

    kFixture.writeExport(branchesWith(8));
    const auto kBelow = invoke({"coverage_floors",
                                "--root",
                                kFixture.root().string(),
                                "--export",
                                (kFixture.root() / "out/coverage/export.json").string(),
                                "--diff",
                                kDiff.string()});
    EXPECT_EQ(kBelow.exitCode, kExitFindings);
    EXPECT_TRUE(contains(kBelow.output, kRuleBelowFloor));
    EXPECT_TRUE(contains(kBelow.output, "tier A"));
    EXPECT_TRUE(contains(kBelow.output, "80.0 percent"));
    EXPECT_TRUE(contains(kBelow.output, "floor of 90 percent"));
}

TEST(Command, RefusesAFloorVerdictWithNoChangedLines) {
    RecordProperty("requirement", "STD-0007:no-change-lands-below-its-tier-floor");
    const testing::RepositoryFixture kFixture("command_empty_diff");
    kFixture.writeExport(branchesWith(10));
    const auto kDiff = kFixture.writeDiff("diff --git a/x b/x\n");
    const auto kRun = invoke({"coverage_floors",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string(),
                              "--diff",
                              kDiff.string()});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "no_changed_lines"));
}

TEST(Command, RefusesToConcludeFromAMalformedExport) {
    RecordProperty("requirement", "STD-0007:llvm-cov-export-is-the-artifact-of-record");
    const testing::RepositoryFixture kFixture("command_bad_export");
    kFixture.write("out/coverage/export.json", "{not json");
    const auto kDiff = kFixture.writeDiff(testing::diffAddingSubjectLines(1, 2));
    const auto kRun = invoke({"coverage_floors",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string(),
                              "--diff",
                              kDiff.string()});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "invalid_json"));
}

TEST(Command, RefusesToConcludeWhenAChangedTranslationUnitIsNotInTheExport) {
    const testing::RepositoryFixture kFixture("command_uncovered_unit");
    kFixture.write("out/coverage/export.json",
                   R"({"version":"3.1.0","type":"llvm.coverage.json.export","data":[{"files":[]}]})");
    const auto kDiff = kFixture.writeDiff(testing::diffAddingSubjectLines(1, 2));
    const auto kRun = invoke({"coverage_floors",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string(),
                              "--diff",
                              kDiff.string()});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "uncovered_changed_file"));
}

TEST(Command, RefusesToConcludeWhenAListedRootDeclaresNoTiers) {
    RecordProperty("requirement", "STD-0007:every-source-unit-carries-a-declared-tier");
    const testing::RepositoryFixture kFixture("command_no_tiers");
    kFixture.remove("tools/subject/tests/verification-tiers.json");
    kFixture.writeExport(branchesWith(10));
    const auto kDiff = kFixture.writeDiff(testing::diffAddingSubjectLines(1, 2));
    const auto kRun = invoke({"coverage_floors",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string(),
                              "--diff",
                              kDiff.string()});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "missing_input"));
}

TEST(Command, PublishesTheWholeTreeFigureWithoutAVerdict) {
    RecordProperty("requirement", "STD-0007:whole-tree-coverage-is-published-and-never-gated");
    const testing::RepositoryFixture kFixture("command_summary");
    kFixture.writeExport(branchesWith(4), "[]", "[[1,1,0,true,true,false],[2,1,3,true,true,false]]");
    const auto kRun = invoke({"coverage_summary",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string()});
    EXPECT_EQ(kRun.exitCode, kExitConformant);
    EXPECT_TRUE(contains(kRun.output, "\"budgetClass\": \"verification_objective\""));
    EXPECT_TRUE(contains(kRun.output, "\"uncoveredLines\""));
    EXPECT_TRUE(contains(kRun.output, "\"partiallyCoveredBranchLines\""));
}

TEST(Command, WritesAReportInsideTheDeclaredWriteRootAndRefusesOneOutsideIt) {
    const testing::RepositoryFixture kFixture("command_report_destination");
    kFixture.writeExport(branchesWith(10));

    const auto kInside = invoke({"coverage_summary",
                                 "--root",
                                 kFixture.root().string(),
                                 "--export",
                                 (kFixture.root() / "out/coverage/export.json").string(),
                                 "--report",
                                 (kFixture.root() / "out/reports/verify/summary.json").string()});
    EXPECT_EQ(kInside.exitCode, kExitConformant);
    EXPECT_TRUE(std::filesystem::exists(kFixture.root() / "out/reports/verify/summary.json"));

    const auto kOutside = invoke({"coverage_summary",
                                  "--root",
                                  kFixture.root().string(),
                                  "--export",
                                  (kFixture.root() / "out/coverage/export.json").string(),
                                  "--report",
                                  (kFixture.root() / "out/escape/summary.json").string()});
    EXPECT_EQ(kOutside.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kOutside.errors, "invalid_path"));
    EXPECT_FALSE(std::filesystem::exists(kFixture.root() / "out/escape/summary.json"));
}

TEST(Command, GeneratesTheRequirementsReportAndNamesTheUnboundCriteria) {
    RecordProperty("requirement",
                   "STD-0007:requirements-report-is-generated-from-executed-tests,"
                   "STD-0007:unbound-criteria-are-visible-and-counted");
    const testing::RepositoryFixture kFixture("command_requirements");
    kFixture.write("out/criteria.json",
                   R"({"criteria":[{"id":"DOC-0001:a","text":"bound","discharge":"automated"},)"
                   R"({"id":"DOC-0001:b","text":"unbound","discharge":"automated"}]})");
    kFixture.write("out/gtest.json",
                   R"({"testsuites":[{"testsuite":[{"name":"A","classname":"S","requirement":"DOC-0001:a"}]}]})");

    const auto kRun = invoke({"requirements_report",
                              "--root",
                              kFixture.root().string(),
                              "--criteria",
                              (kFixture.root() / "out/criteria.json").string(),
                              "--test-report",
                              (kFixture.root() / "out/gtest.json").string()});
    EXPECT_EQ(kRun.exitCode, kExitConformant);
    EXPECT_TRUE(contains(kRun.output, "\"boundCriteria\": 1"));
    EXPECT_TRUE(contains(kRun.output, "\"unboundCriteria\": 1"));
    EXPECT_TRUE(contains(kRun.output, "DOC-0001:b"));
}

TEST(Command, ReportsATestBoundToACriterionTheInventoryDoesNotDeclare) {
    const testing::RepositoryFixture kFixture("command_requirements_drift");
    kFixture.write("out/criteria.json", R"({"criteria":[{"id":"DOC-0001:a","text":"t","discharge":"automated"}]})");
    kFixture.write("out/gtest.json",
                   R"({"testsuites":[{"testsuite":[{"name":"A","classname":"S","requirement":"DOC-0001:z"}]}]})");
    const auto kRun = invoke({"requirements_report",
                              "--root",
                              kFixture.root().string(),
                              "--criteria",
                              (kFixture.root() / "out/criteria.json").string(),
                              "--test-report",
                              (kFixture.root() / "out/gtest.json").string()});
    EXPECT_EQ(kRun.exitCode, kExitFindings);
    EXPECT_TRUE(contains(kRun.output, kRuleUndeclaredCriterion));
}

TEST(Command, FallsBackToTheRepositoryInventoryWhenNoneIsNamed) {
    const testing::RepositoryFixture kFixture("command_default_inventory");
    kFixture.write("out/gtest.json", R"({"testsuites":[]})");
    const auto kRun = invoke({"requirements_report",
                              "--root",
                              kFixture.root().string(),
                              "--test-report",
                              (kFixture.root() / "out/gtest.json").string()});
    // The fixture has no inventory at the default path, so the absence is what
    // the tool reports rather than an empty and reassuring report.
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "missing_input"));
}

TEST(Command, KeepsItsArtifactsOutOfTheEvidenceChain) {
    RecordProperty("requirement", "STD-0007:coverage-artifacts-stay-out-of-the-evidence-chain");
    const testing::RepositoryFixture kFixture("command_evidence_class");
    kFixture.writeExport(branchesWith(10));
    const auto kRun = invoke({"coverage_summary",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string()});
    ASSERT_EQ(kRun.exitCode, kExitConformant);
    EXPECT_TRUE(contains(kRun.output, "\"evidenceClass\": \"correctness_and_hygiene\""));
    for (const std::string_view kRecordKind :
         {"raw_run_receipt", "evidence_set", "evaluation_receipt", "baseline_record", "recordKind"}) {
        EXPECT_FALSE(contains(kRun.output, kRecordKind)) << kRecordKind;
    }
}

TEST(TierDeclarations, ReadsTheDeclarationsOfEveryListedRootInThisRepository) {
    RecordProperty("requirement", "STD-0007:every-source-unit-carries-a-declared-tier");
    auto tiers = readTierIndex(testing::repositoryRoot());
    ASSERT_TRUE(tiers.has_value()) << tiers.error().message;
    EXPECT_TRUE(tiers->presentButUndeclared.empty())
        << "first undeclared unit: " << (tiers->presentButUndeclared.empty() ? "" : tiers->presentButUndeclared.at(0));
    EXPECT_TRUE(tiers->declaredButAbsent.empty())
        << "first stale declaration: " << (tiers->declaredButAbsent.empty() ? "" : tiers->declaredButAbsent.at(0));
    EXPECT_TRUE(tiers->units.contains("tools/rf_verify/src/floors.cpp"));
}

TEST(TierDeclarations, RejectsADeclarationThatIsNotOne) {
    const testing::RepositoryFixture kFixture("tiers_bad_declaration");
    const std::vector<std::string_view> kCases{
        R"([{"path": "src/parser.cpp", "tier": "Z", "reason": "unknown tier"}])",
        R"([{"path": "src/parser.cpp", "tier": "A"}])",
        R"([{"tier": "A", "reason": "no path"}])",
        R"([{"path": "src/parser.cpp", "tier": "A", "reason": "one"},
            {"path": "src/parser.cpp", "tier": "H", "reason": "twice"}])",
    };
    for (const auto& units : kCases) {
        kFixture.writeTiers(units);
        auto tiers = readTierIndex(kFixture.root());
        ASSERT_FALSE(tiers.has_value()) << units;
        EXPECT_EQ(tiers.error().code, FailureCode::InvalidJson);
    }

    kFixture.write("tools/subject/tests/verification-tiers.json", R"({"schemaVersion": 1})");
    auto noUnits = readTierIndex(kFixture.root());
    ASSERT_FALSE(noUnits.has_value());
    EXPECT_EQ(noUnits.error().code, FailureCode::InvalidJson);
}

TEST(TierDeclarations, RejectsARootIndexThatIsNotOne) {
    const testing::RepositoryFixture kFixture("tiers_bad_index");
    kFixture.write("repository.json", R"({"modules": []})");
    auto noTools = readTierIndex(kFixture.root());
    ASSERT_FALSE(noTools.has_value());
    EXPECT_EQ(noTools.error().code, FailureCode::InvalidJson);

    kFixture.writeIndex(R"([7])");
    auto notAPath = readTierIndex(kFixture.root());
    ASSERT_FALSE(notAPath.has_value());
    EXPECT_EQ(notAPath.error().code, FailureCode::InvalidJson);

    kFixture.writeIndex(R"(["tool.json"])");
    auto noRoot = readTierIndex(kFixture.root());
    ASSERT_FALSE(noRoot.has_value());
    EXPECT_EQ(noRoot.error().code, FailureCode::InvalidJson);
}

TEST(TierDeclarations, ReportsBothDirectionsOfDrift) {
    const testing::RepositoryFixture kFixture("tiers_drift");
    kFixture.write("tools/subject/src/added.cpp", "int added() { return 0; }\n");
    kFixture.writeTiers(R"([{"path": "src/parser.cpp", "tier": "A", "reason": "the subject unit"},
                            {"path": "src/removed.cpp", "tier": "O", "reason": "no longer there"}])");
    auto tiers = readTierIndex(kFixture.root());
    ASSERT_TRUE(tiers.has_value()) << tiers.error().message;
    EXPECT_EQ(tiers->presentButUndeclared, (std::vector<std::string>{"tools/subject/src/added.cpp"}));
    EXPECT_EQ(tiers->declaredButAbsent, (std::vector<std::string>{"tools/subject/src/removed.cpp"}));
}

TEST(TierDeclarations, SkipsAListedRootWithNoMaintainedSource) {
    const testing::RepositoryFixture kFixture("tiers_no_source");
    kFixture.remove("tools/subject/src");
    kFixture.remove("tools/subject/tests/verification-tiers.json");
    auto tiers = readTierIndex(kFixture.root());
    ASSERT_TRUE(tiers.has_value()) << tiers.error().message;
    EXPECT_TRUE(tiers->units.empty());
}

TEST(Command, RefusesEveryFlagGivenWithNoValue) {
    for (const std::string_view kFlag : {"--root", "--export", "--diff", "--criteria", "--test-report", "--report"}) {
        EXPECT_EQ(invoke({"coverage_floors", std::string(kFlag)}).exitCode, kExitUsage) << kFlag;
    }
    EXPECT_EQ(invoke({"coverage_floors", "--diff", "d.diff"}).exitCode, kExitUsage)
        << "a floor verdict needs both the export and the diff";
}

TEST(Command, RefusesEveryOperationAgainstARootThatIsNotThisRepository) {
    const testing::RepositoryFixture kFixture("command_bad_root_every_operation");
    kFixture.remove("repository.json");
    const auto kExport = (kFixture.root() / "out/coverage/export.json").string();
    const auto kDiff = kFixture.writeDiff(testing::diffAddingSubjectLines(1, 2));
    for (const auto& kArguments : std::vector<std::vector<std::string>>{
             {"coverage_floors", "--root", kFixture.root().string(), "--export", kExport, "--diff", kDiff.string()},
             {"coverage_summary", "--root", kFixture.root().string(), "--export", kExport},
             {"requirements_report", "--root", kFixture.root().string(), "--test-report", kExport}}) {
        const auto kRun = invoke(kArguments);
        EXPECT_EQ(kRun.exitCode, kExitToolFailure) << kArguments.front();
        EXPECT_TRUE(contains(kRun.errors, "missing_input")) << kArguments.front();
    }
}

TEST(Command, RefusesToConcludeFromAMalformedDiff) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    const testing::RepositoryFixture kFixture("command_bad_diff");
    kFixture.writeExport(branchesWith(10));
    const auto kDiff = kFixture.writeDiff("+++ b/tools/subject/src/parser.cpp\n@@ -1,0 +x @@\n+a\n");
    const auto kRun = invoke({"coverage_floors",
                              "--root",
                              kFixture.root().string(),
                              "--export",
                              (kFixture.root() / "out/coverage/export.json").string(),
                              "--diff",
                              kDiff.string()});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "malformed_diff"));
}

TEST(Command, RefusesAWholeTreeSummaryFromAMalformedExportOrAnUndeclaredRoot) {
    const testing::RepositoryFixture kFixture("command_summary_failures");
    kFixture.write("out/coverage/export.json", "{not json");
    const auto kExport = (kFixture.root() / "out/coverage/export.json").string();
    const auto kBad = invoke({"coverage_summary", "--root", kFixture.root().string(), "--export", kExport});
    EXPECT_EQ(kBad.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kBad.errors, "invalid_json"));

    kFixture.writeExport(branchesWith(10));
    kFixture.remove("tools/subject/tests/verification-tiers.json");
    const auto kNoTiers = invoke({"coverage_summary", "--root", kFixture.root().string(), "--export", kExport});
    EXPECT_EQ(kNoTiers.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kNoTiers.errors, "missing_input"));
}

TEST(Command, RefusesARequirementsReportFromACriteriaInventoryItCannotRead) {
    const testing::RepositoryFixture kFixture("command_bad_criteria");
    kFixture.write("out/report.json", R"({"testsuites":[]})");
    const auto kRun = invoke({"requirements_report",
                              "--root",
                              kFixture.root().string(),
                              "--criteria",
                              (kFixture.root() / "out/absent-criteria.json").string(),
                              "--test-report",
                              (kFixture.root() / "out/report.json").string()});
    EXPECT_EQ(kRun.exitCode, kExitToolFailure);
    EXPECT_TRUE(contains(kRun.errors, "missing_input"));
}

} // namespace rawframe::tool::verify
