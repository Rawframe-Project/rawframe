#include "repository_validator.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

constexpr std::string_view kRegistryMedia = "application/vnd.rawframe.evidence.metric-registry.v1+json";
constexpr std::string_view kPolicyMedia = "application/vnd.rawframe.evidence.evaluation-policy.v1+json";

// A root built for one case. Membership is about what the tree holds against
// what the index claims, so proving it needs a tree the case owns rather than
// the repository, which by construction always agrees with itself.
std::filesystem::path scratchRoot(std::string_view name) {
    const std::filesystem::path kRoot =
        std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "membership" / std::filesystem::path(std::string(name));
    std::error_code error;
    std::filesystem::remove_all(kRoot, error);
    std::filesystem::create_directories(kRoot / "evidence" / "registries", error);
    std::filesystem::create_directories(kRoot / "evidence" / "policies", error);
    return kRoot;
}

void writeFile(const std::filesystem::path& path, std::string_view bytes) {
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string authority(std::string_view authorityClass, std::string_view path, std::string_view mediaType) {
    std::string entry = R"({"authorityClass":")";
    entry += authorityClass;
    entry += R"(","mediaType":")";
    entry += mediaType;
    entry += R"(","path":")";
    entry += path;
    entry += R"("})";
    return entry;
}

std::filesystem::path writeIndex(const std::filesystem::path& root, const std::vector<std::string>& authorities) {
    std::string bytes = R"({"authorities":[)";
    bool separate = false;
    for (const std::string& authority : authorities) {
        if (separate) {
            bytes += ",";
        }
        separate = true;
        bytes += authority;
    }
    bytes += R"(],"indexGeneration":1,"recordKind":"evidence_index","schemaVersion":1})";
    const std::filesystem::path kPath = root / "evidence" / "evidence.json";
    writeFile(kPath, bytes);
    return kPath;
}

} // namespace

TEST(RepositoryValidator, AcceptsTaskOneRepository) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = validateRepository(kRoot);
    ASSERT_TRUE(result.has_value()) << result.error().path << ": " << result.error().message;
    ASSERT_EQ(result->tools.size(), 1U);
    EXPECT_EQ(result->tools.front().id, "rawframe.tool.evidence");
    EXPECT_EQ(result->tools.front().cmakeTarget, "rawframe_tool_rf_evidence");
}

TEST(RepositoryValidator, ResolvesTheRegisteredEvidenceIndex) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = validateRepository(kRoot);
    ASSERT_TRUE(result.has_value()) << result.error().path << ": " << result.error().message;
    EXPECT_EQ(result->evidenceIndexPath, "evidence/evidence.json");
    ASSERT_EQ(result->evidenceAuthorities.size(), 2U);
    EXPECT_EQ(result->evidenceAuthorities.front().authorityClass, "evaluation_policy");
    EXPECT_EQ(result->evidenceAuthorities.back().authorityClass, "metric_registry");
}

// The anchor for every membership rejection below.
TEST(EvidenceMembership, AdmitsATreeHoldingExactlyWhatTheIndexClaims) {
    const auto kRoot = scratchRoot("agrees");
    writeFile(kRoot / "evidence/registries/registry.json", "{}");
    const auto kIndex =
        writeIndex(kRoot, {authority("metric_registry", "evidence/registries/registry.json", kRegistryMedia)});
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_TRUE(authorities.has_value()) << authorities.error().path << ": " << authorities.error().message;
    ASSERT_EQ(authorities->size(), 1U);
    EXPECT_TRUE(rejectUnlistedEvidenceAuthorities(kRoot, "evidence/evidence.json", *authorities).has_value());
}

TEST(EvidenceMembership, RefusesAnIndexNamingAPathThatDoesNotExist) {
    const auto kRoot = scratchRoot("absent");
    const auto kIndex =
        writeIndex(kRoot, {authority("metric_registry", "evidence/registries/absent.json", kRegistryMedia)});
    EXPECT_FALSE(readEvidenceAuthorities(kRoot, kIndex).has_value());
}

TEST(EvidenceMembership, RefusesAnIndexListingOneAuthorityTwice) {
    const auto kRoot = scratchRoot("twice");
    writeFile(kRoot / "evidence/registries/registry.json", "{}");
    const std::string kEntry = authority("metric_registry", "evidence/registries/registry.json", kRegistryMedia);
    const auto kIndex = writeIndex(kRoot, {kEntry, kEntry});
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_FALSE(authorities.has_value());
    EXPECT_EQ(authorities.error().code, FailureCode::OwnershipCollision);
}

TEST(EvidenceMembership, RefusesAMediaTypeDisagreeingWithTheDeclaredClass) {
    const auto kRoot = scratchRoot("disagrees");
    writeFile(kRoot / "evidence/registries/registry.json", "{}");
    const auto kIndex =
        writeIndex(kRoot, {authority("metric_registry", "evidence/registries/registry.json", kPolicyMedia)});
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_FALSE(authorities.has_value());
    EXPECT_EQ(authorities.error().code, FailureCode::InvalidManifest);
}

// A baseline record is the class this generation deliberately does not have.
// Tier 0 cannot create, promote, activate, or trust a baseline, so an index
// naming one is refused here as well as by the index schema.
TEST(EvidenceMembership, RefusesABaselineAuthorityClass) {
    const auto kRoot = scratchRoot("unknown_class");
    writeFile(kRoot / "evidence/baseline.json", "{}");
    const auto kIndex = writeIndex(kRoot, {authority("baseline_record", "evidence/baseline.json", kRegistryMedia)});
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_FALSE(authorities.has_value());
    EXPECT_EQ(authorities.error().code, FailureCode::InvalidManifest);
}

TEST(EvidenceMembership, RefusesAnEntryEscapingTheRepository) {
    const auto kRoot = scratchRoot("escapes");
    const auto kIndex = writeIndex(kRoot, {authority("metric_registry", "../outside.json", kRegistryMedia)});
    EXPECT_FALSE(readEvidenceAuthorities(kRoot, kIndex).has_value());
}

// The one failure a membership list cannot report by reading itself. Without
// this the model would degrade into scanning by accident: whatever sat under
// `evidence/` would be part of the repository, listed or not.
TEST(EvidenceMembership, RefusesAnAuthorityPresentButNotListed) {
    const auto kRoot = scratchRoot("unlisted");
    writeFile(kRoot / "evidence/registries/registry.json", "{}");
    writeFile(kRoot / "evidence/registries/smuggled.json", "{}");
    const auto kIndex =
        writeIndex(kRoot, {authority("metric_registry", "evidence/registries/registry.json", kRegistryMedia)});
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_TRUE(authorities.has_value());
    auto status = rejectUnlistedEvidenceAuthorities(kRoot, "evidence/evidence.json", *authorities);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
    EXPECT_EQ(status.error().path, "evidence/registries/smuggled.json");
}

TEST(EvidenceMembership, RefusesALinkInsideMaintainedEvidence) {
    const auto kRoot = scratchRoot("link");
    writeFile(kRoot / "evidence/registries/registry.json", "{}");
    const auto kIndex =
        writeIndex(kRoot, {authority("metric_registry", "evidence/registries/registry.json", kRegistryMedia)});
    std::error_code error;
    std::filesystem::create_symlink(
        kRoot / "evidence/registries/registry.json", kRoot / "evidence/registries/linked.json", error);
    if (error) {
        GTEST_SKIP() << "creating a symbolic link is not permitted here";
    }
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_TRUE(authorities.has_value());
    auto status = rejectUnlistedEvidenceAuthorities(kRoot, "evidence/evidence.json", *authorities);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidPath);
}

TEST(EvidenceMembership, RefusesAnAuthorityReachedThroughALink) {
    const auto kRoot = scratchRoot("linked_entry");
    writeFile(kRoot / "evidence/registries/real.json", "{}");
    std::error_code error;
    std::filesystem::create_symlink(
        kRoot / "evidence/registries/real.json", kRoot / "evidence/registries/registry.json", error);
    if (error) {
        GTEST_SKIP() << "creating a symbolic link is not permitted here";
    }
    const auto kIndex =
        writeIndex(kRoot, {authority("metric_registry", "evidence/registries/registry.json", kRegistryMedia)});
    auto authorities = readEvidenceAuthorities(kRoot, kIndex);
    ASSERT_FALSE(authorities.has_value());
    EXPECT_EQ(authorities.error().code, FailureCode::InvalidPath);
}

} // namespace rawframe::tool::evidence
