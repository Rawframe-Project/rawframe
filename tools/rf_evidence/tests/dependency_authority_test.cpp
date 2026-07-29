#include "dependency_authority.h"
#include "repository_validator.h"

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

RepositorySnapshot realSnapshot() {
    auto snapshot = validateRepository(realRoot());
    EXPECT_TRUE(snapshot.has_value()) << snapshot.error().path << ": " << snapshot.error().message;
    return snapshot.value_or(RepositorySnapshot{});
}

// Rejection cases need an authority set that differs from the real one in
// exactly one respect. Copying the real authority files into a scratch root
// and mutating one of them keeps every other input identical, so a failure
// names the mutation rather than some unrelated difference.
std::filesystem::path scratchRootFor(std::string_view name) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "dependency_authority" / name;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot / "third_party");
    for (const auto* kFile : {"catalog.json", "artifacts.lock.json", "toolchain.lock.json"}) {
        std::filesystem::copy_file(realRoot() / "third_party" / kFile, kRoot / "third_party" / kFile);
    }
    std::filesystem::copy(realRoot() / "third_party" / "licenses",
                          kRoot / "third_party" / "licenses",
                          std::filesystem::copy_options::recursive);
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

// Replaces the first occurrence only. A silent no-op would make a rejection
// case pass for the wrong reason, so the caller asserts the substring existed.
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

} // namespace

// The harness itself is verified first. If a faithful copy were rejected, every
// rejection case below would pass without proving anything.
TEST(DependencyAuthority, AcceptsAFaithfulCopyOfTheRealAuthoritySet) {
    const auto kRoot = scratchRootFor("baseline");
    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    EXPECT_TRUE(status.has_value()) << status.error().path << ": " << status.error().message;
}

TEST(DependencyAuthority, RejectsACollidingCatalogIdentity) {
    const auto kRoot = scratchRootFor("catalog_collision");
    mutateFile(kRoot / "third_party/catalog.json", "\"id\": \"library.simdjson\"", "\"id\": \"library.openssl\"");

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::OwnershipCollision);
}

// Catalog identity is compared without case sensitivity, so a differently
// cased duplicate must collide rather than register as a second dependency.
TEST(DependencyAuthority, RejectsACollidingCatalogIdentityRegardlessOfCase) {
    const auto kRoot = scratchRootFor("catalog_collision_case");
    mutateFile(kRoot / "third_party/catalog.json", "\"id\": \"library.simdjson\"", "\"id\": \"Library.OpenSSL\"");

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::OwnershipCollision);
}

TEST(DependencyAuthority, RejectsAnArtifactBoundToAnUnknownCatalogIdentity) {
    const auto kRoot = scratchRootFor("artifact_unknown_catalog");
    mutateFile(kRoot / "third_party/artifacts.lock.json",
               "\"catalogId\": \"host.ubuntu\"",
               "\"catalogId\": \"host.no_such_dependency\"");

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
}

// License material is bound by exact bytes. Editing the text without editing
// the index must fail, or the offline license record would be unverifiable.
TEST(DependencyAuthority, RejectsLicenseMaterialWhoseBytesNoLongerMatchTheIndex) {
    const auto kRoot = scratchRootFor("license_digest");
    const auto kMaterial = kRoot / "third_party/licenses/THIRD_PARTY_NOTICES.md";
    auto text = readText(kMaterial);
    ASSERT_FALSE(text.empty());
    text.front() = static_cast<char>(text.front() ^ 0x20);
    writeText(kMaterial, text);

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::VerificationFailed);
}

TEST(DependencyAuthority, RejectsALicenseIndexOfAnUnsupportedGeneration) {
    const auto kRoot = scratchRootFor("license_generation");
    mutateFile(kRoot / "third_party/licenses/index.json", "\"schemaVersion\": 1", "\"schemaVersion\": 2");

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
}

TEST(DependencyAuthority, RejectsAnAuthorityFileWhoseRootIsNotAnObject) {
    const auto kRoot = scratchRootFor("catalog_not_object");
    writeText(kRoot / "third_party/catalog.json", "[]");

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidJson);
}

TEST(DependencyAuthority, RejectsAMissingAuthorityFile) {
    const auto kRoot = scratchRootFor("catalog_missing");
    std::filesystem::remove(kRoot / "third_party/catalog.json");

    auto status = validateDependencyAuthorities(kRoot, realSnapshot());
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::MissingInput);
}

// The final cross-check reads the tool manifests rather than the lock files,
// so it is driven by mutating the snapshot instead of the scratch root.
TEST(DependencyAuthority, RejectsAToolDeclaringAnUnknownThirdPartyDependency) {
    const auto kRoot = scratchRootFor("tool_unknown_dependency");
    auto snapshot = realSnapshot();
    ASSERT_FALSE(snapshot.tools.empty());
    snapshot.tools.front().thirdPartyDependencies.emplace_back("library.no_such_dependency");

    auto status = validateDependencyAuthorities(kRoot, snapshot);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
}

TEST(DependencyAuthority, RejectsAToolDeclaringAnUnknownManagedTool) {
    const auto kRoot = scratchRootFor("tool_unknown_managed_tool");
    auto snapshot = realSnapshot();
    ASSERT_FALSE(snapshot.tools.empty());
    snapshot.tools.front().managedToolDependencies.emplace_back("tool.no_such_managed_tool");

    auto status = validateDependencyAuthorities(kRoot, snapshot);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code, FailureCode::InvalidManifest);
}

// A declared dependency that does exist must still be admitted, so the two
// cases above are proven to reject the unknown identity rather than the act of
// declaring anything at all.
TEST(DependencyAuthority, AdmitsAToolDeclaringAKnownDependency) {
    const auto kRoot = scratchRootFor("tool_known_dependency");
    auto snapshot = realSnapshot();
    ASSERT_FALSE(snapshot.tools.empty());
    snapshot.tools.front().thirdPartyDependencies.emplace_back("library.openssl");
    snapshot.tools.front().managedToolDependencies.emplace_back("tool.jsonschema_oracle");

    auto status = validateDependencyAuthorities(kRoot, snapshot);
    EXPECT_TRUE(status.has_value()) << status.error().path << ": " << status.error().message;
}

} // namespace rawframe::tool::evidence
