#include "offline_verifier.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

// Every case below drives a synthetic repository root rather than the real one.
// The real tree is already verified end to end by the acceptance fixture, and it
// cannot be mutated one rule at a time: its cache objects are hundreds of
// megabytes and its prepared trees are produced by the sync lane. A synthetic
// root with one small artifact exercises exactly the same lock walk, digest
// check, and prepared-identity check, and it can be broken in one place at a
// time.
//
// The blob is fixed text with a precomputed digest, so the lock this suite
// writes is an independent statement of the artifact identity rather than
// whatever the tool's own hasher happened to produce.
constexpr std::string_view kBlob = "rawframe artifact\n";
constexpr std::string_view kBlobDigest = "8c399dab12cf9ec725e269d44d7f2f17441a5b874b4e26ee9f9dc7d0657bb157";
// Same length, different bytes. Placing this at the path the lock names is how a
// substituted artifact reaches the verifier with a plausible size.
constexpr std::string_view kImposter = "rawframe Artifact\n";

// The host is passed as an argument, but the prepared executable name the
// verifier expects is chosen at compile time, so these cases name the host they
// are compiled for. That keeps the prepared-tree cases below asserting the file
// the running lane would actually execute.
#ifdef _WIN32
constexpr std::string_view kHost = "windows-x86_64";
constexpr std::string_view kSigningToolId = "tool.cosign.windows_x86_64";
constexpr std::string_view kSigningToolPath = "out/prepared/windows-x86_64/tools/cosign/bin/cosign.exe";
constexpr std::string_view kArchiveToolId = "tool.archive_extractor.windows_x86_64";
constexpr std::string_view kOtherPlatform = "platform.linux";
#else
constexpr std::string_view kHost = "linux-x86_64";
constexpr std::string_view kSigningToolId = "tool.cosign.linux_x86_64";
constexpr std::string_view kSigningToolPath = "out/prepared/linux-x86_64/tools/cosign/bin/cosign";
constexpr std::string_view kArchiveToolId = "tool.archive_extractor.linux_x86_64";
constexpr std::string_view kOtherPlatform = "platform.windows";
#endif

std::filesystem::path scratchRootFor(std::string_view name) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "offline_verifier" / name;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot / "third_party");
    return kRoot;
}

void writeFile(const std::filesystem::path& path, std::string_view text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
}

void writeLock(const std::filesystem::path& root, std::string_view body) {
    writeFile(root / "third_party/artifacts.lock.json", body);
}

// Places the blob where the verifier derives its path from the recorded digest,
// which is the layout the content-addressed cache uses.
void writeCacheObject(const std::filesystem::path& root, std::string_view digest, std::string_view content) {
    writeFile(root / "out/cache/objects" / std::string(digest.substr(0, 2)) / std::string(digest), content);
}

std::string artifactEntry(std::string_view id, std::string_view digest, std::string_view byteSize) {
    return std::string(R"({"id": ")") + std::string(id) + R"(", "platform": "platform.any", "sha256": ")" +
           std::string(digest) + R"(", "byteSize": )" + std::string(byteSize) + "}";
}

std::string lockWith(std::string_view entries) {
    return std::string(R"({"artifacts": [)") + std::string(entries) + "]}\n";
}

} // namespace

// The anchor for everything below. A well-formed lock whose cache object matches
// must survive the entire artifact walk and stop only where a synthetic root
// genuinely cannot continue, namely at the prepared-tool marker the sync lane
// produces. Any rejection case that failed earlier for an unrelated reason would
// contradict this.
TEST(OfflineVerifier, CompletesTheArtifactWalkForALockWhoseCacheObjectMatches) {
    const auto kRoot = scratchRootFor("baseline");
    writeLock(kRoot, lockWith(artifactEntry("tool.example", kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::MissingInput);
    EXPECT_NE(report.error().path.find("out/prepared/" + std::string(kHost) + "/tools/cmake/.rf-prepared.json"),
              std::string::npos)
        << report.error().path;
}

TEST(OfflineVerifier, RejectsAnArtifactWhoseCacheObjectIsAbsent) {
    const auto kRoot = scratchRootFor("absent_object");
    writeLock(kRoot, lockWith(artifactEntry("tool.example", kBlobDigest, "18")));

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::MissingInput);
    EXPECT_EQ(report.error().path, "tool.example");
    EXPECT_NE(report.error().message.find("verified cache object is absent"), std::string::npos)
        << report.error().message;
}

// The size is checked before the digest, so it must reject on its own rather
// than leaning on the hash to notice afterwards.
TEST(OfflineVerifier, RejectsACacheObjectWhoseByteSizeDisagreesWithTheLock) {
    const auto kRoot = scratchRootFor("wrong_size");
    writeLock(kRoot, lockWith(artifactEntry("tool.example", kBlobDigest, "19")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::VerificationFailed);
    EXPECT_NE(report.error().message.find("byte size does not match"), std::string::npos) << report.error().message;
}

// This is the substitution the whole verifier exists to catch: the right name,
// the right length, the wrong bytes.
TEST(OfflineVerifier, RejectsACacheObjectWhoseContentDoesNotHashToItsRecordedDigest) {
    const auto kRoot = scratchRootFor("wrong_digest");
    writeLock(kRoot, lockWith(artifactEntry("tool.example", kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kImposter);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::VerificationFailed);
    EXPECT_NE(report.error().message.find("SHA-256 does not match"), std::string::npos) << report.error().message;
}

// Two entries claiming one identity is an ownership collision, not a redundant
// restatement, because the second could name different bytes.
TEST(OfflineVerifier, RejectsADuplicateArtifactIdentity) {
    const auto kRoot = scratchRootFor("duplicate_id");
    writeLock(kRoot,
              lockWith(artifactEntry("tool.example", kBlobDigest, "18") + ", " +
                       artifactEntry("tool.example", kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::OwnershipCollision);
    EXPECT_EQ(report.error().path, "tool.example");
}

// A size recorded as a string or a float is not a size. Accepting either would
// let the comparison above succeed against a value nobody wrote down exactly.
TEST(OfflineVerifier, RejectsAnArtifactByteSizeThatIsNotAnUnsignedInteger) {
    const auto kRoot = scratchRootFor("bad_bytesize");
    writeLock(kRoot, lockWith(artifactEntry("tool.example", kBlobDigest, "\"18\"")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidJson);
    EXPECT_NE(report.error().message.find("byteSize"), std::string::npos) << report.error().message;
}

TEST(OfflineVerifier, RejectsAnArtifactMissingItsRecordedDigest) {
    const auto kRoot = scratchRootFor("missing_digest");
    writeLock(kRoot, lockWith(R"({"id": "tool.example", "platform": "platform.any", "byteSize": 18})"));

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidJson);
    EXPECT_NE(report.error().message.find("sha256"), std::string::npos) << report.error().message;
}

TEST(OfflineVerifier, RejectsALockWithNoArtifactsArray) {
    const auto kRoot = scratchRootFor("no_artifacts");
    writeLock(kRoot, "{\"tools\": []}\n");

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidJson);
    EXPECT_NE(report.error().message.find("no artifacts array"), std::string::npos) << report.error().message;
}

TEST(OfflineVerifier, RejectsALockThatIsNotAnObject) {
    const auto kRoot = scratchRootFor("not_an_object");
    writeLock(kRoot, "[]\n");

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidJson);
}

TEST(OfflineVerifier, RejectsAMissingLock) {
    const auto kRoot = scratchRootFor("missing_lock");

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::MissingInput);
}

// An empty selection is not a clean verification. A lock that happens to name
// nothing for this host has verified nothing, and reporting success would make
// the whole check vacuous.
TEST(OfflineVerifier, RejectsALockThatSelectsNoInputsForTheHost) {
    const auto kRoot = scratchRootFor("empty_selection");
    writeLock(kRoot,
              lockWith(std::string(R"({"id": "tool.example", "platform": ")") + std::string(kOtherPlatform) +
                       R"(", "sha256": ")" + std::string(kBlobDigest) + R"(", "byteSize": 18})"));

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::MissingInput);
    EXPECT_NE(report.error().message.find("selects no inputs"), std::string::npos) << report.error().message;
}

TEST(OfflineVerifier, RejectsAHostOutsideTheTaskMatrix) {
    const auto kRoot = scratchRootFor("unsupported_host");
    writeLock(kRoot, lockWith(artifactEntry("tool.example", kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, "darwin-arm64");
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::UnsupportedHost);
    EXPECT_EQ(report.error().path, "darwin-arm64");
}

// A verified cache object is not a verified installation. The signing tool is
// extracted into the prepared tree, and the file that is actually executed has
// to carry the identity the lock recorded.
TEST(OfflineVerifier, RejectsAPreparedSigningToolThatWasNeverInstalled) {
    const auto kRoot = scratchRootFor("prepared_absent");
    writeLock(kRoot, lockWith(artifactEntry(kSigningToolId, kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::MissingInput);
    EXPECT_EQ(report.error().path, kSigningToolId);
    EXPECT_NE(report.error().message.find("prepared file is absent"), std::string::npos) << report.error().message;
}

TEST(OfflineVerifier, RejectsAPreparedSigningToolWhoseInstalledBytesWereReplaced) {
    const auto kRoot = scratchRootFor("prepared_replaced");
    writeLock(kRoot, lockWith(artifactEntry(kSigningToolId, kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);
    writeFile(kRoot / kSigningToolPath, kImposter);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::VerificationFailed);
    EXPECT_NE(report.error().message.find("prepared file SHA-256 does not match"), std::string::npos)
        << report.error().message;
}

// An extracted archive is admitted by the identity of the files taken out of it,
// so a lock entry that names no required files leaves the prepared tree
// unverifiable and must be rejected rather than treated as nothing to check.
TEST(OfflineVerifier, RejectsAPreparedArchiveThatDeclaresNoRequiredFileIdentities) {
    const auto kRoot = scratchRootFor("archive_without_required_files");
    writeLock(kRoot, lockWith(artifactEntry(kArchiveToolId, kBlobDigest, "18")));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidManifest);
    EXPECT_NE(report.error().message.find("required-file identities"), std::string::npos) << report.error().message;
}

TEST(OfflineVerifier, RejectsAPreparedArchiveWhoseRequiredFileIdentityIsIncomplete) {
    const auto kRoot = scratchRootFor("archive_incomplete_required_file");
    const std::string kEntry = std::string(R"({"id": ")") + std::string(kArchiveToolId) +
                               R"(", "platform": "platform.any", "sha256": ")" + std::string(kBlobDigest) +
                               R"(", "byteSize": 18, )" +
                               R"("archive": {"requiredFiles": [{"path": "7z", "byteSize": 18}]}})";
    writeLock(kRoot, lockWith(kEntry));
    writeCacheObject(kRoot, kBlobDigest, kBlob);

    auto report = verifyOfflineInputs(kRoot, kHost);
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidManifest);
    EXPECT_NE(report.error().message.find("identity is incomplete"), std::string::npos) << report.error().message;
}

} // namespace rawframe::tool::evidence
