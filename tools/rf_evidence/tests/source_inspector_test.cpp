#include "report_writer.h"
#include "repository_validator.h"
#include "source_inspector.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

// STD-0001 states its thresholds as "at or above", so every boundary is asserted
// exactly. The classifier is constexpr, so the boundaries are also proven at
// compile time and cannot regress silently into a runtime-only check.
static_assert(sourceGateForLines(0) == SourceGate::Ok);
static_assert(sourceGateForLines(599) == SourceGate::Ok);
static_assert(sourceGateForLines(600) == SourceGate::OwnershipReviewRequired);
static_assert(sourceGateForLines(999) == SourceGate::OwnershipReviewRequired);
static_assert(sourceGateForLines(1'000) == SourceGate::FeatureGrowthStopped);
static_assert(sourceGateForLines(1'499) == SourceGate::FeatureGrowthStopped);

TEST(SourceInspector, AdmitsFilesBelowTheOwnershipReviewThreshold) {
    EXPECT_EQ(sourceGateForLines(0), SourceGate::Ok);
    EXPECT_EQ(sourceGateForLines(kOwnershipReviewLines - 1), SourceGate::Ok);
}

TEST(SourceInspector, RejectsFurtherGrowthAtTheOwnershipReviewThreshold) {
    EXPECT_EQ(sourceGateForLines(kOwnershipReviewLines), SourceGate::OwnershipReviewRequired);
    EXPECT_EQ(sourceGateForLines(kFeatureGrowthStopLines - 1), SourceGate::OwnershipReviewRequired);
    EXPECT_EQ(sourceGateSeverity(SourceGate::OwnershipReviewRequired), "warning");
    EXPECT_EQ(sourceGateName(SourceGate::OwnershipReviewRequired), "ownership_review_required");
}

TEST(SourceInspector, RejectsUnrelatedGrowthAtTheFeatureGrowthStopThreshold) {
    EXPECT_EQ(sourceGateForLines(kFeatureGrowthStopLines), SourceGate::FeatureGrowthStopped);
    EXPECT_EQ(sourceGateForLines(kHardFailureLines - 1), SourceGate::FeatureGrowthStopped);
    EXPECT_EQ(sourceGateSeverity(SourceGate::FeatureGrowthStopped), "blocking");
    EXPECT_EQ(sourceGateName(SourceGate::FeatureGrowthStopped), "feature_growth_stopped");
}

TEST(SourceInspector, PreservesTheExactStandardThresholds) {
    EXPECT_EQ(kOwnershipReviewLines, 600U);
    EXPECT_EQ(kFeatureGrowthStopLines, 1'000U);
    EXPECT_EQ(kHardFailureLines, 1'500U);
}

TEST(SourceInspector, AdmitsFileLengthsBelowTheHardFailureGate) {
    EXPECT_TRUE(admitPhysicalLineCount("tools/rf_evidence/src/example.cpp", 0).has_value());
    EXPECT_TRUE(admitPhysicalLineCount("tools/rf_evidence/src/example.cpp", kHardFailureLines - 1).has_value());
}

TEST(SourceInspector, RejectsFileLengthsAtOrAboveTheHardFailureGate) {
    auto atGate = admitPhysicalLineCount("tools/rf_evidence/src/example.cpp", kHardFailureLines);
    ASSERT_FALSE(atGate.has_value());
    EXPECT_EQ(atGate.error().code, FailureCode::LimitExceeded);
    EXPECT_EQ(atGate.error().path, "tools/rf_evidence/src/example.cpp");
    EXPECT_NE(atGate.error().message.find("1500-line hard failure gate"), std::string::npos);

    EXPECT_FALSE(admitPhysicalLineCount("tools/rf_evidence/src/example.cpp", kHardFailureLines + 1).has_value());
}

TEST(SourceInspector, AttributesOwnershipToTheDeclaringToolManifest) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto snapshot = validateRepository(kRoot);
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().path << ": " << snapshot.error().message;
    ASSERT_FALSE(snapshot->tools.empty());

    auto result = inspectSourceOwnership(kRoot);
    ASSERT_TRUE(result.has_value()) << result.error().path << ": " << result.error().message;
    ASSERT_FALSE(result->empty());

    // The owner must come from the manifest, not from a constant inside the
    // inspector, so every reported owner has to be one a manifest declares.
    std::set<std::string> declaredOwners;
    for (const auto& tool : snapshot->tools) {
        EXPECT_FALSE(tool.owner.empty()) << tool.id;
        declaredOwners.insert(tool.owner);
    }
    for (const auto& entry : *result) {
        EXPECT_TRUE(declaredOwners.contains(entry.owner)) << entry.path << ": " << entry.owner;
    }
}

TEST(SourceInspector, ClassifiesEveryMaintainedFileAgainstTheMeasuredLineCount) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = inspectSourceOwnership(kRoot);
    ASSERT_TRUE(result.has_value()) << result.error().path << ": " << result.error().message;
    ASSERT_FALSE(result->empty());
    for (const auto& entry : *result) {
        EXPECT_EQ(entry.gate, sourceGateForLines(entry.lines)) << entry.path;
        EXPECT_LT(entry.lines, kHardFailureLines) << entry.path;
    }
}

// STD-0001 exempts generated and vendored material from the numerical
// thresholds and declares that classification by location, never by size. The
// rule is checked directly, because no tool root currently contains either kind
// and a repository sweep alone could pass while the rule was inverted.
TEST(SourceInspector, DeclaresExemptionByLocationRatherThanBySize) {
    EXPECT_EQ(classifyRepositoryPath("tools/rf_evidence/src/command.cpp"), SourceClassification::Maintained);
    EXPECT_EQ(classifyRepositoryPath("out/reports/task-0001/generated.h"), SourceClassification::Generated);
    EXPECT_EQ(classifyRepositoryPath("third_party/vcpkg/toolchains/windows-x86_64.cmake"),
              SourceClassification::Vendored);

    // A prefix is a path segment, not a string fragment. `outbound/` and
    // `third_party_notes/` are maintained source that merely start with the
    // same letters.
    EXPECT_EQ(classifyRepositoryPath("outbound/thing.cpp"), SourceClassification::Maintained);
    EXPECT_EQ(classifyRepositoryPath("third_party_notes/thing.cpp"), SourceClassification::Maintained);

    EXPECT_FALSE(isExemptFromLineThresholds(SourceClassification::Maintained));
    EXPECT_TRUE(isExemptFromLineThresholds(SourceClassification::Generated));
    EXPECT_TRUE(isExemptFromLineThresholds(SourceClassification::Vendored));
}

// Every file the sweep reports today is maintained, because tool roots are
// segregated from the exempt locations. Asserting it keeps that segregation a
// measured property instead of an assumption about the directory layout.
TEST(SourceInspector, ReportsOnlyMaintainedFilesWhileToolRootsStaySegregated) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = inspectSourceOwnership(kRoot);
    ASSERT_TRUE(result.has_value()) << result.error().path << ": " << result.error().message;
    ASSERT_FALSE(result->empty());
    for (const auto& entry : *result) {
        EXPECT_EQ(entry.classification, SourceClassification::Maintained) << entry.path;
    }
}

TEST(SourceInspector, ReportsThresholdsAndGateCountsMachineReadably) {
    const std::vector<SourceOwnershipEntry> kEntries{
        SourceOwnershipEntry{"tools/rf_evidence/src/small.cpp", 10, "rawframe.build_engineering", SourceGate::Ok},
        SourceOwnershipEntry{"tools/rf_evidence/src/review.cpp",
                             kOwnershipReviewLines,
                             "rawframe.build_engineering",
                             SourceGate::OwnershipReviewRequired},
        SourceOwnershipEntry{"tools/rf_evidence/src/stopped.cpp",
                             kFeatureGrowthStopLines,
                             "rawframe.build_engineering",
                             SourceGate::FeatureGrowthStopped},
        SourceOwnershipEntry{"third_party/vendored/huge.h",
                             kHardFailureLines * 2,
                             "rawframe.build_engineering",
                             SourceGate::Ok,
                             SourceClassification::Vendored},
    };

    const std::string kReport = buildSourceOwnershipReport(kEntries);
    EXPECT_NE(kReport.find("\"ownershipReviewLines\":600"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"featureGrowthStopLines\":1000"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"hardFailureLines\":1500"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"ownershipReviewCount\":1"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"featureGrowthStopCount\":1"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"gate\":\"ownership_review_required\""), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"gate\":\"feature_growth_stopped\""), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"severity\":\"blocking\""), std::string::npos) << kReport;

    // The exempt entry is longer than the hard failure gate on purpose: STD-0001
    // exempts it from the numerical thresholds, so it must be counted apart and
    // must not appear in either gate count.
    EXPECT_NE(kReport.find("\"fileCount\":4"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"maintainedFileCount\":3"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"exemptFileCount\":1"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"classification\":\"vendored\",\"exempt\":true"), std::string::npos) << kReport;
    EXPECT_NE(kReport.find("\"classification\":\"maintained\",\"exempt\":false"), std::string::npos) << kReport;
}

} // namespace rawframe::tool::evidence
