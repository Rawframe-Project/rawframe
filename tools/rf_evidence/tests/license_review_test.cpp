#include "license_review.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

const std::filesystem::path& realRoot() {
    static const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    return kRoot;
}

// Every case below differs from the real authority set in exactly one respect.
// Copying the real catalog and license tree into a scratch root and mutating one
// value keeps every other input identical, so a rejection names the mutation
// rather than some unrelated difference between two hand-written fixtures.
std::filesystem::path scratchRootFor(std::string_view name) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "license_review" / name;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot / "third_party");
    std::filesystem::copy_file(realRoot() / "third_party/catalog.json", kRoot / "third_party/catalog.json");
    std::filesystem::copy(
        realRoot() / "third_party/licenses", kRoot / "third_party/licenses", std::filesystem::copy_options::recursive);
    return kRoot;
}

std::string readText(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

void writeText(const std::filesystem::path& path, std::string_view text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

// Replaces the first occurrence only. A silent no-op would make a rejection case
// pass for the wrong reason, so the caller asserts the substring existed.
bool replaceFirst(std::string& text, std::string_view from, std::string_view to) {
    const auto kAt = text.find(from);
    if (kAt == std::string::npos) {
        return false;
    }
    text.replace(kAt, from.size(), to);
    return true;
}

void mutateFile(const std::filesystem::path& path, std::string_view from, std::string_view to) {
    auto text = readText(path);
    ASSERT_TRUE(replaceFirst(text, from, to)) << "fixture text not found in " << path.generic_string() << ": " << from;
    writeText(path, text);
}

std::filesystem::path indexIn(const std::filesystem::path& root) {
    return root / "third_party/licenses/index.json";
}

} // namespace

// The harness is verified first. If a faithful copy were rejected, every
// rejection case below would pass without proving anything.
TEST(LicenseReview, AcceptsAFaithfulCopyOfTheRealLicenseAuthority) {
    const auto kRoot = scratchRootFor("baseline");
    auto review = reviewLicenses(kRoot);
    ASSERT_TRUE(review.has_value()) << review.error().path << ": " << review.error().message;
    EXPECT_FALSE(review->materials.empty());
    EXPECT_FALSE(review->entries.empty());
    EXPECT_GT(review->catalogEntryCount, 0U);
}

// The index records an exact byte length beside each digest. Both are checked,
// so the shorter check must reject on its own rather than relying on the digest
// to notice afterwards.
TEST(LicenseReview, RejectsMaterialWhoseRecordedByteLengthIsWrong) {
    const auto kRoot = scratchRootFor("byte_length");
    mutateFile(indexIn(kRoot), "\"byteSize\": 1499", "\"byteSize\": 1500");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::VerificationFailed);
    EXPECT_NE(review.error().message.find("byte length"), std::string::npos) << review.error().message;
}

TEST(LicenseReview, RejectsMaterialWhoseRecordedDigestIsWrong) {
    const auto kRoot = scratchRootFor("digest");
    mutateFile(indexIn(kRoot),
               "02decff634c03ed91bd0d73a4db4ccce44a81ce61637cbad41392500f851d7f3",
               "02decff634c03ed91bd0d73a4db4ccce44a81ce61637cbad41392500f851d7f4");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::VerificationFailed);
    EXPECT_NE(review.error().message.find("digest"), std::string::npos) << review.error().message;
}

// A digest check is only as good as the path it is applied to. Material outside
// the license directory is rejected before it is read, so the index cannot be
// used to attest a file elsewhere in the tree.
TEST(LicenseReview, RejectsMaterialOutsideTheLicenseDirectory) {
    const auto kRoot = scratchRootFor("material_path");
    mutateFile(indexIn(kRoot),
               "\"path\": \"third_party/licenses/cmake/LICENSE.rst\"",
               "\"path\": \"third_party/catalog.json\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::InvalidPath);
    EXPECT_NE(review.error().message.find("must live under"), std::string::npos) << review.error().message;
}

TEST(LicenseReview, RejectsADuplicateMaterialPath) {
    const auto kRoot = scratchRootFor("duplicate_material");
    mutateFile(indexIn(kRoot),
               "\"path\": \"third_party/licenses/googletest/LICENSE\"",
               "\"path\": \"third_party/licenses/cmake/LICENSE.rst\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::OwnershipCollision);
    EXPECT_NE(review.error().message.find("material path is duplicated"), std::string::npos) << review.error().message;
}

TEST(LicenseReview, RejectsAMaterialByteSizeThatIsNotAPositiveInteger) {
    const auto kRoot = scratchRootFor("material_bytesize_shape");
    mutateFile(indexIn(kRoot), "\"byteSize\": 1499", "\"byteSize\": 0");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::InvalidJson);
}

TEST(LicenseReview, RejectsADuplicateEntryIdentity) {
    const auto kRoot = scratchRootFor("duplicate_entry");
    mutateFile(indexIn(kRoot), "\"id\": \"license.cmake\"", "\"id\": \"license.ninja\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::OwnershipCollision);
    EXPECT_NE(review.error().message.find("duplicate entry ID"), std::string::npos) << review.error().message;
}

TEST(LicenseReview, RejectsAnEntryReferencingUnindexedMaterial) {
    const auto kRoot = scratchRootFor("unindexed_material");
    mutateFile(indexIn(kRoot),
               "\"materialPath\": \"third_party/licenses/THIRD_PARTY_NOTICES.md\"",
               "\"materialPath\": \"third_party/licenses/NOT_INDEXED.md\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::InvalidManifest);
    EXPECT_NE(review.error().message.find("unindexed"), std::string::npos) << review.error().message;
}

// Approval is a closed set. An unrecognized value must reject rather than fall
// through as merely not restricted, which would silently admit a dependency
// nobody approved.
TEST(LicenseReview, RejectsAnUnknownApprovalState) {
    const auto kRoot = scratchRootFor("approval_state");
    mutateFile(indexIn(kRoot), "\"approval\": \"approved\"", "\"approval\": \"pending\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::InvalidManifest);
    EXPECT_NE(review.error().message.find("approval"), std::string::npos) << review.error().message;
}

TEST(LicenseReview, RejectsAnEntryReferencingAnUnknownCatalogIdentity) {
    const auto kRoot = scratchRootFor("unknown_catalog_id");
    mutateFile(indexIn(kRoot), "\"tool.cmake\"", "\"tool.no_such_catalog_entry\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::MissingInput);
    EXPECT_NE(review.error().message.find("unknown catalog ID"), std::string::npos) << review.error().message;
}

// Coverage must be exactly one entry per catalog identity. Two entries claiming
// one dependency is an ownership collision, not a redundancy.
TEST(LicenseReview, RejectsACatalogIdentityCoveredByMoreThanOneEntry) {
    const auto kRoot = scratchRootFor("double_coverage");
    mutateFile(indexIn(kRoot), "\"tool.ninja\"", "\"tool.cmake\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::OwnershipCollision);
    EXPECT_NE(review.error().message.find("more than one license entry"), std::string::npos) << review.error().message;
}

// The catalog is the license authority and the index is a projection of it.
// When they disagree, the index does not win.
TEST(LicenseReview, RejectsAnIndexThatDisagreesWithTheCatalogLicenseAuthority) {
    const auto kRoot = scratchRootFor("catalog_disagreement");
    mutateFile(indexIn(kRoot), "\"spdxExpression\": \"BSD-3-Clause\"", "\"spdxExpression\": \"MIT\"");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::VerificationFailed);
    EXPECT_NE(review.error().message.find("catalog license authority"), std::string::npos) << review.error().message;
}

TEST(LicenseReview, RejectsAnIndexThatIsNotReadableJson) {
    const auto kRoot = scratchRootFor("unreadable_index");
    writeText(indexIn(kRoot), "{ this is not json");

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::InvalidJson);
}

TEST(LicenseReview, RejectsAMissingIndex) {
    const auto kRoot = scratchRootFor("missing_index");
    std::filesystem::remove(indexIn(kRoot));

    auto review = reviewLicenses(kRoot);
    ASSERT_FALSE(review.has_value());
    EXPECT_EQ(review.error().code, FailureCode::MissingInput);
}

} // namespace rawframe::tool::evidence
