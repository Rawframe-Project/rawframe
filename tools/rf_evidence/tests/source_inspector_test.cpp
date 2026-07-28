#include "report_writer.h"
#include "source_inspector.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>

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
}

} // namespace rawframe::tool::evidence
