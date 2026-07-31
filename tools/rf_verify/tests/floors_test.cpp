#include "coverage_summary.h"
#include "floors.h"
#include "verify_fixture.h"

#include <algorithm>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rawframe::tool::verify {

namespace {

struct Subject {
    CoverageExport coverage;
    ChangedLines changed;
    TierIndex tiers;
};

// Ten branch regions on ten changed lines, of which `coveredRegions` are covered
// on both outcomes and the rest on neither. That makes the measured percentage
// exactly `coveredRegions * 10`, so a case can sit on either side of a floor
// deliberately rather than approximately.
Subject subjectWith(VerificationTier tier, int coveredRegions) {
    Subject subject;
    CoverageFile file;
    file.path = "tools/subject/src/parser.cpp";
    for (int index = 0; index < 10; ++index) {
        BranchRegion region;
        region.line = static_cast<std::uint32_t>(index + 1);
        region.trueCount = index < coveredRegions ? 1 : 0;
        region.falseCount = index < coveredRegions ? 1 : 0;
        file.branches.push_back(region);
        subject.changed.files["tools/subject/src/parser.cpp"].insert(region.line);
    }
    subject.coverage.files.emplace(file.path, file);

    TierDeclaration declaration;
    declaration.path = file.path;
    declaration.tier = tier;
    declaration.reason = "the subject unit";
    subject.tiers.units.emplace(declaration.path, declaration);
    return subject;
}

bool hasFinding(const FindingSet& findings, std::string_view ruleId) {
    return std::ranges::any_of(findings.findings, [ruleId](const Finding& finding) {
        return finding.ruleId == ruleId;
    });
}

} // namespace

TEST(Floors, PassesAChangeAtOrAboveItsTierFloor) {
    RecordProperty("requirement", "STD-0007:no-change-lands-below-its-tier-floor");
    for (const auto& [kTier, kRegions] : {std::pair{VerificationTier::Ordinary, 8},
                                          std::pair{VerificationTier::Authority, 9},
                                          std::pair{VerificationTier::Hostile, 10}}) {
        Subject subject = subjectWith(kTier, kRegions);
        auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
        ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
        ASSERT_EQ(evaluation->units.size(), 1U);
        EXPECT_TRUE(evaluation->units.at(0).meetsFloor) << tierName(kTier);
        EXPECT_TRUE(evaluation->findings.empty()) << tierName(kTier);
        EXPECT_EQ(evaluation->units.at(0).floorPercent, tierBranchFloorPercent(kTier));
    }
}

TEST(Floors, FailsAChangeOneStepBelowItsTierFloor) {
    RecordProperty("requirement", "STD-0007:no-change-lands-below-its-tier-floor");
    for (const auto& [kTier, kRegions] : {std::pair{VerificationTier::Ordinary, 7},
                                          std::pair{VerificationTier::Authority, 8},
                                          std::pair{VerificationTier::Hostile, 9}}) {
        Subject subject = subjectWith(kTier, kRegions);
        auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
        ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
        ASSERT_EQ(evaluation->units.size(), 1U);
        EXPECT_FALSE(evaluation->units.at(0).meetsFloor) << tierName(kTier);
        ASSERT_FALSE(evaluation->findings.empty()) << tierName(kTier);
        const Finding& kFinding = evaluation->findings.findings.at(0);
        EXPECT_EQ(kFinding.ruleId, kRuleBelowFloor);
        // The message names the tier, the measured value, and the floor, because
        // a verdict that says only "below the floor" cannot be acted on.
        EXPECT_NE(kFinding.message.find(std::string("tier ") + std::string(tierName(kTier))), std::string::npos);
        EXPECT_NE(kFinding.message.find("percent"), std::string::npos);
        EXPECT_NE(kFinding.message.find(std::to_string(tierBranchFloorPercent(kTier))), std::string::npos);
    }
}

TEST(Floors, MeasuresOnlyTheChangedLines) {
    Subject subject = subjectWith(VerificationTier::Hostile, 2);
    // Only the two covered lines were touched, so the eight uncovered ones do
    // not belong to this change and the floor is met.
    subject.changed.files["tools/subject/src/parser.cpp"] = {1, 2};
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_TRUE(evaluation->units.at(0).meetsFloor);
    EXPECT_EQ(evaluation->units.at(0).changedConditions, 4);
    EXPECT_EQ(evaluation->units.at(0).coveredConditions, 4);
}

TEST(Floors, ReportsThePartiallyCoveredLinesRatherThanOnlyAPercentage) {
    Subject subject = subjectWith(VerificationTier::Authority, 8);
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_EQ(evaluation->units.at(0).uncoveredBranchLines, (std::vector<std::uint32_t>{9, 10}));
}

TEST(Floors, MeetsTheFloorWhenTheChangedLinesCarryNoBranches) {
    Subject subject = subjectWith(VerificationTier::Hostile, 0);
    subject.changed.files["tools/subject/src/parser.cpp"] = {900, 901};
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_EQ(evaluation->units.at(0).changedConditions, 0);
    EXPECT_TRUE(evaluation->units.at(0).meetsFloor);
    EXPECT_TRUE(evaluation->findings.empty());
}

TEST(Floors, RequiresMcdcOnlyOnTierHChangedDecisions) {
    RecordProperty("requirement", "STD-0007:tier-h-decisions-are-covered-to-mcdc");
    McdcDecision uncovered;
    uncovered.line = 3;
    uncovered.conditionCount = 2;
    McdcTestVector only;
    only.conditions = {McdcTestVector::ConditionValue::True, McdcTestVector::ConditionValue::True};
    only.executed = true;
    only.result = true;
    uncovered.vectors.push_back(only);

    Subject hostile = subjectWith(VerificationTier::Hostile, 10);
    hostile.coverage.files.at("tools/subject/src/parser.cpp").decisions.push_back(uncovered);
    auto hostileEvaluation = evaluateFloors(hostile.changed, hostile.coverage, hostile.tiers);
    ASSERT_TRUE(hostileEvaluation.has_value()) << hostileEvaluation.error().message;
    EXPECT_EQ(hostileEvaluation->units.at(0).changedDecisions, 1U);
    EXPECT_EQ(hostileEvaluation->units.at(0).uncoveredDecisions, 1U);
    EXPECT_TRUE(hasFinding(hostileEvaluation->findings, kRuleMcdcUncovered));

    Subject authority = subjectWith(VerificationTier::Authority, 10);
    authority.coverage.files.at("tools/subject/src/parser.cpp").decisions.push_back(uncovered);
    auto authorityEvaluation = evaluateFloors(authority.changed, authority.coverage, authority.tiers);
    ASSERT_TRUE(authorityEvaluation.has_value()) << authorityEvaluation.error().message;
    EXPECT_EQ(authorityEvaluation->units.at(0).changedDecisions, 0U);
    EXPECT_TRUE(authorityEvaluation->findings.empty());
}

TEST(Floors, AcceptsATierHDecisionThatIsIndependentlyCovered) {
    McdcDecision covered;
    covered.line = 3;
    covered.conditionCount = 1;
    McdcTestVector on;
    on.conditions = {McdcTestVector::ConditionValue::True};
    on.executed = true;
    on.result = true;
    McdcTestVector off;
    off.conditions = {McdcTestVector::ConditionValue::False};
    off.executed = true;
    off.result = false;
    covered.vectors = {on, off};

    Subject subject = subjectWith(VerificationTier::Hostile, 10);
    subject.coverage.files.at("tools/subject/src/parser.cpp").decisions.push_back(covered);
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_EQ(evaluation->units.at(0).uncoveredDecisions, 0U);
    EXPECT_TRUE(evaluation->findings.empty());
}

TEST(Floors, ReportsAChangedSourceUnitWithNoDeclaredTier) {
    RecordProperty("requirement", "STD-0007:every-source-unit-carries-a-declared-tier");
    Subject subject = subjectWith(VerificationTier::Ordinary, 10);
    subject.tiers.units.clear();
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_TRUE(evaluation->units.empty());
    EXPECT_TRUE(hasFinding(evaluation->findings, kRuleUndeclaredTier));
}

TEST(Floors, ReportsADeclarationForAUnitThatIsNotThereAndAUnitWithNoDeclaration) {
    RecordProperty("requirement", "STD-0007:every-source-unit-carries-a-declared-tier");
    Subject subject = subjectWith(VerificationTier::Ordinary, 10);
    subject.tiers.declaredButAbsent.emplace_back("tools/subject/src/removed.cpp");
    subject.tiers.presentButUndeclared.emplace_back("tools/subject/src/added.cpp");
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_TRUE(hasFinding(evaluation->findings, kRuleStaleTier));
    EXPECT_TRUE(hasFinding(evaluation->findings, kRuleUndeclaredTier));
}

TEST(Floors, RefusesToConcludeWhenTheExportDoesNotDescribeAChangedTranslationUnit) {
    RecordProperty("requirement", "STD-0007:llvm-cov-export-is-the-artifact-of-record");
    Subject subject = subjectWith(VerificationTier::Ordinary, 10);
    subject.coverage.files.clear();
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_FALSE(evaluation.has_value());
    EXPECT_EQ(evaluation.error().code, FailureCode::UncoveredChangedFile);
    EXPECT_EQ(evaluation.error().path, "tools/subject/src/parser.cpp");
}

TEST(Floors, CountsRatherThanFaultsAChangedHeaderWithNoInstrumentedCode) {
    Subject subject = subjectWith(VerificationTier::Ordinary, 10);
    subject.coverage.files.clear();
    subject.changed.files.clear();
    subject.changed.files["tools/subject/src/parser.h"].insert(1);
    TierDeclaration declaration;
    declaration.path = "tools/subject/src/parser.h";
    declaration.tier = VerificationTier::Ordinary;
    subject.tiers.units.emplace(declaration.path, declaration);

    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_TRUE(evaluation->findings.empty());
    EXPECT_EQ(evaluation->changedHeadersWithoutInstrumentedCode, 1U);
    EXPECT_TRUE(evaluation->units.empty());
}

TEST(Floors, CountsChangedPathsThatAreNotSourceUnitsRatherThanDroppingThem) {
    Subject subject = subjectWith(VerificationTier::Ordinary, 10);
    subject.changed.files["repository.json"].insert(3);
    subject.changed.files["tools/subject/tests/parser_test.cpp"].insert(4);
    auto evaluation = evaluateFloors(subject.changed, subject.coverage, subject.tiers);
    ASSERT_TRUE(evaluation.has_value()) << evaluation.error().message;
    EXPECT_EQ(evaluation->changedNonSourcePaths, 2U);
}

TEST(CoverageSummaryReport, PublishesTheWholeTreeFigureAndTheUncoveredSetWithoutAVerdict) {
    RecordProperty("requirement",
                   "STD-0007:whole-tree-coverage-is-published-and-never-gated,"
                   "STD-0007:the-uncovered-set-is-the-review-artifact");
    Subject subject = subjectWith(VerificationTier::Hostile, 6);
    CoverageFile& file = subject.coverage.files.at("tools/subject/src/parser.cpp");
    file.summary.lines = CoverageCounts{20, 15};
    file.summary.branches = CoverageCounts{20, 12};
    file.summary.regions = CoverageCounts{30, 21};
    file.summary.mcdc = CoverageCounts{2, 1};
    file.lineCounts = {{1, 4}, {2, 0}, {3, 0}};
    subject.coverage.droppedForeignFiles = 3;

    auto summary = summarizeCoverage(subject.coverage, subject.tiers);
    ASSERT_TRUE(summary.has_value()) << summary.error().message;
    EXPECT_EQ(summary->totals.lines.count, 20);
    EXPECT_EQ(summary->totals.lines.covered, 15);
    EXPECT_EQ(summary->totals.branches.covered, 12);
    EXPECT_EQ(summary->totals.mcdc.count, 2);
    EXPECT_EQ(summary->droppedForeignFiles, 3U);
    ASSERT_EQ(summary->files.size(), 1U);
    EXPECT_EQ(summary->files.at(0).tier, "H");
    EXPECT_EQ(summary->files.at(0).uncoveredLines, (std::vector<std::uint32_t>{2, 3}));
    EXPECT_EQ(summary->files.at(0).partiallyCoveredBranchLines, (std::vector<std::uint32_t>{7, 8, 9, 10}));
}

TEST(CoverageSummaryReport, ReportsAnUncoveredDecisionAndAUnitWithNoDeclaredTier) {
    Subject subject = subjectWith(VerificationTier::Ordinary, 10);
    subject.tiers.units.clear();
    McdcDecision uncovered;
    uncovered.line = 5;
    uncovered.conditionCount = 1;
    subject.coverage.files.at("tools/subject/src/parser.cpp").decisions.push_back(uncovered);

    auto summary = summarizeCoverage(subject.coverage, subject.tiers);
    ASSERT_TRUE(summary.has_value()) << summary.error().message;
    EXPECT_TRUE(summary->files.at(0).tier.empty());
    EXPECT_EQ(summary->files.at(0).uncoveredDecisionLines, (std::vector<std::uint32_t>{5}));
}

} // namespace rawframe::tool::verify
