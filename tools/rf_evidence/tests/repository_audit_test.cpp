#include "license_review.h"
#include "path_audit.h"
#include "repository_validator.h"
#include "shipping_closure.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace rawframe::tool::evidence {

TEST(LicenseReview, AcceptsTheAdmittedCatalogAndVerifiesMaterial) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto review = reviewLicenses(kRoot);
    ASSERT_TRUE(review.has_value()) << review.error().path << ": " << review.error().message;
    // Twenty-one catalog entries under eighteen policies: the four pinned
    // first-party GitHub Actions share one MIT policy over one notice section,
    // and every catalog entry is still covered exactly once.
    EXPECT_EQ(review->catalogEntryCount, 21U);
    EXPECT_EQ(review->entries.size(), 18U);
    ASSERT_FALSE(review->materials.empty());

    // Two deliberately restricted dependencies, for different reasons. The
    // offline AGPL schema oracle may not be redistributed at all. The Windows
    // container base layer is Microsoft-licensed and its derived image is kept
    // to a private registry package, which is a condition rather than a
    // prohibition.
    EXPECT_EQ(review->restrictedCount, 2U);
    std::vector<std::string> restricted;
    for (const auto& entry : review->entries) {
        if (entry.approval == "restricted") {
            restricted.push_back(entry.licenseId + " " + entry.redistribution);
        }
    }
    std::ranges::sort(restricted);
    ASSERT_EQ(restricted.size(), 2U);
    EXPECT_EQ(restricted.at(0), "license.sourcemeta_jsonschema forbidden");
    EXPECT_EQ(restricted.at(1), "license.windows_servercore conditional");
}

TEST(PathAudit, DeliveredFilesStayInsideTheTaskEnvelope) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    for (const auto& violation : audit->envelopeViolations) {
        ADD_FAILURE() << violation.classification << ": " << violation.path;
    }
    EXPECT_GT(audit->envelopeFileCount, 0U);
    EXPECT_GT(audit->preexistingFileCount, 0U);
    EXPECT_EQ(audit->envelopeFiles.size(), audit->envelopeFileCount);
    EXPECT_TRUE(std::ranges::is_sorted(audit->envelopeFiles));

    // Root .clang-tidy joined the envelope through the accepted 2026-07-16
    // amendment, and the historical staging directories are classified
    // landing-excluded instead of unclassified.
    EXPECT_TRUE(std::ranges::find(audit->envelopeFiles, ".clang-tidy") != audit->envelopeFiles.end());
    for (const auto& entry : audit->stagingRootEntries) {
        EXPECT_EQ(entry.classification, "historical_staging_landing_excluded");
    }
    EXPECT_TRUE(std::ranges::is_sorted(audit->stagingRootEntries, {}, &PathAuditEntry::path));
}

namespace {

// A tree built to be audited. The real repository holds only maintained
// evidence, so proving that generated material would be reported needs a root
// that holds some.
std::filesystem::path evidenceAuditRoot(std::string_view name, std::string_view relativeFile) {
    const std::filesystem::path kRoot =
        std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "evidence_audit" / std::filesystem::path(std::string(name));
    std::error_code error;
    std::filesystem::remove_all(kRoot, error);
    std::filesystem::create_directories(kRoot, error);
    std::ofstream index(kRoot / "repository.json", std::ios::binary | std::ios::trunc);
    index << "{}";
    index.close();

    const std::filesystem::path kFile = kRoot / std::filesystem::path(std::string(relativeFile));
    std::filesystem::create_directories(kFile.parent_path(), error);
    std::ofstream content(kFile, std::ios::binary | std::ios::trunc);
    content << "{}";
    return kRoot;
}

bool reportsViolation(const PathAudit& audit, std::string_view path) {
    return std::ranges::any_of(audit.envelopeViolations, [path](const PathAuditEntry& entry) {
        return entry.path == path && entry.classification == "outside_envelope";
    });
}

} // namespace

// Decision 7. Maintained and generated stay apart, and the audit proves it
// rather than a convention asserting it. The three maintained shapes are
// admitted; anything else beneath the root is reported.
TEST(PathAudit, AdmitsTheThreeMaintainedEvidenceShapes) {
    for (const std::string_view kPath : {"evidence/evidence.json",
                                         "evidence/registries/metric-registry-v2.json",
                                         "evidence/policies/tier0-evaluation-policy-v2.json"}) {
        const auto kRoot = evidenceAuditRoot("maintained", kPath);
        auto audit = auditRepositoryPaths(kRoot);
        ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
        EXPECT_TRUE(audit->envelopeViolations.empty()) << kPath;
    }
}

TEST(PathAudit, ReportsAGeneratedArtifactPlacedUnderMaintainedEvidence) {
    const auto kRoot = evidenceAuditRoot("generated", "evidence/out/report.json");
    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(reportsViolation(*audit, "evidence/out/report.json"));
}

TEST(PathAudit, ReportsABlobPlacedUnderMaintainedEvidence) {
    const auto kRoot = evidenceAuditRoot("blob", "evidence/blobs/sha256/ab/cd.json");
    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(reportsViolation(*audit, "evidence/blobs/sha256/ab/cd.json"));
}

// Tier 0 cannot create, promote, activate, or trust a baseline. A file that
// looked like one would be the first step toward pretending otherwise, so the
// audit reports it as readily as it reports a generated blob.
TEST(PathAudit, ReportsABaselineRecordPlacedUnderMaintainedEvidence) {
    const auto kRoot = evidenceAuditRoot("baseline", "evidence/baselines/anchor.json");
    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(reportsViolation(*audit, "evidence/baselines/anchor.json"));
}

TEST(PathAudit, ReportsANestedDirectoryBeneathAMaintainedClass) {
    const auto kRoot = evidenceAuditRoot("nested", "evidence/registries/archive/old.json");
    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(reportsViolation(*audit, "evidence/registries/archive/old.json"));
}

TEST(PathAudit, TheMaintainedTreeHoldsNoBaselineOrActiveRole) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    std::error_code error;
    EXPECT_FALSE(std::filesystem::exists(kRoot / "evidence/baselines", error));
    EXPECT_FALSE(std::filesystem::exists(kRoot / "evidence/roles", error));
    auto audit = auditRepositoryPaths(kRoot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    EXPECT_TRUE(audit->envelopeViolations.empty());
}

TEST(ShippingClosure, RepositoryToolCannotEnterShipping) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto snapshot = validateRepository(kRoot);
    ASSERT_TRUE(snapshot.has_value()) << snapshot.error().path << ": " << snapshot.error().message;
    auto audit = auditShippingClosure(snapshot->root, *snapshot);
    ASSERT_TRUE(audit.has_value()) << audit.error().path << ": " << audit.error().message;
    for (const auto& check : audit->checks) {
        EXPECT_TRUE(check.pass) << check.check << ": " << check.subject;
    }
    EXPECT_TRUE(audit->allPassed());
}

} // namespace rawframe::tool::evidence
