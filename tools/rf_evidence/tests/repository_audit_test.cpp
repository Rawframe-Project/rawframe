#include "license_review.h"
#include "path_audit.h"
#include "repository_validator.h"
#include "shipping_closure.h"

#include <algorithm>
#include <filesystem>
#include <gtest/gtest.h>

namespace rawframe::tool::evidence {

TEST(LicenseReview, AcceptsTaskOneCatalogAndVerifiesMaterial) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto review = reviewLicenses(kRoot);
    ASSERT_TRUE(review.has_value()) << review.error().path << ": " << review.error().message;
    EXPECT_EQ(review->catalogEntryCount, 16U);
    EXPECT_EQ(review->entries.size(), 16U);
    ASSERT_FALSE(review->materials.empty());

    // The offline AGPL schema oracle is the one deliberately restricted,
    // non-redistributable dependency; everything else is approved.
    EXPECT_EQ(review->restrictedCount, 1U);
    const auto kRestricted = std::ranges::find(review->entries, "restricted", &LicenseReviewEntry::approval);
    ASSERT_NE(kRestricted, review->entries.end());
    EXPECT_EQ(kRestricted->licenseId, "license.sourcemeta_jsonschema");
    EXPECT_EQ(kRestricted->redistribution, "forbidden");
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
