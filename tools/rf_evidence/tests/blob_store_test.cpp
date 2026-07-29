#include "blob_store.h"
#include "path_policy.h"
#include "sha256.h"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace rawframe::tool::evidence {

// Defined in file_security_test.cpp, which links into the same test binary.
// Declared here rather than in a shared header because this Task's envelope
// names exactly two test files, and a third would widen it. It returns an empty
// string on success and a diagnostic when the host cannot build the subject.
std::string createIndirection(const std::filesystem::path& link, const std::filesystem::path& target);

namespace {

// The reference content for every case below. Rejection cases mutate exactly
// one thing about it or about the store around it, so a case cannot pass
// because storage stopped working altogether.
constexpr std::string_view kContent = R"({"a":1})";
constexpr std::string_view kContentDigest = "sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862";

std::filesystem::path scratch(std::string_view label) {
    static std::atomic<unsigned long long> leaves{0};
    const std::filesystem::path kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "blob_store" /
                                        (std::string(label) + "." + std::to_string(leaves.fetch_add(1U)));
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    return kRoot;
}

std::filesystem::path writeFile(const std::filesystem::path& path, std::string_view content) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    return path;
}

std::string readAllBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream content;
    content << input.rdbuf();
    return std::move(content).str();
}

std::size_t countBlobShapedFiles(const std::filesystem::path& blobsRoot) {
    std::size_t found = 0;
    std::error_code error;
    for (const auto& kEntry : std::filesystem::recursive_directory_iterator(blobsRoot, error)) {
        if (kEntry.is_regular_file() && kEntry.path().filename().string().size() == 62U) {
            ++found;
        }
    }
    return found;
}

struct Fixture {
    std::filesystem::path root;
    std::filesystem::path blobsRoot;
    std::filesystem::path source;

    [[nodiscard]] BlobStore store() const {
        return BlobStore(blobsRoot);
    }
};

Fixture fixture(std::string_view label, std::string_view content = kContent) {
    Fixture built;
    built.root = scratch(label);
    built.blobsRoot = built.root / "out/evidence/v1/blobs";
    built.source = writeFile(built.root / "source.json", content);
    return built;
}

BlobRejection rejectionOfDigest(std::string_view digest) {
    auto status = validateBlobDigest(digest);
    EXPECT_FALSE(status.has_value()) << "expected a rejection for: " << digest;
    if (status) {
        return BlobRejection::StoreIoFailure;
    }
    return status.error().rejection;
}

} // namespace

// The anchor.
TEST(BlobStore, PublishesContentAndReportsItsIdentity) {
    const auto kFixture = fixture("publish");
    auto identity = kFixture.store().put(kFixture.source);
    ASSERT_TRUE(identity.has_value()) << (identity ? std::string{} : identity.error().detail);
    EXPECT_EQ(identity->digest, kContentDigest);
    EXPECT_EQ(identity->byteLength, kContent.size());
}

// Verification item 3: the split is two characters and then sixty-two, against
// a literal rather than against the expression that produced it.
TEST(BlobStore, DerivesTheExactSpecifiedPathFromTheDigestAlone) {
    const BlobStore kStore(std::filesystem::path("/store/blobs"));
    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());
    EXPECT_EQ(path->generic_string(),
              "/store/blobs/sha256/01/5abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862");
}

TEST(BlobStore, StoresContentAtTheDerivedPath) {
    const auto kFixture = fixture("derived");
    const BlobStore kStore = kFixture.store();
    ASSERT_TRUE(kStore.put(kFixture.source).has_value());
    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());
    EXPECT_TRUE(std::filesystem::exists(*path));
    EXPECT_EQ(readAllBytes(*path), kContent);
}

TEST(BlobStore, AcceptsTheUnmutatedDigest) {
    EXPECT_TRUE(validateBlobDigest(kContentDigest).has_value());
}

// Verification item 4. Every one of these is refused by the digest validator,
// which is what makes path safety structural: after this function returns, no
// traversal character can be in the derived path because none is in the
// admitted alphabet.
TEST(BlobStore, RejectsEveryMalformedDigestAtTheValidator) {
    const std::vector<std::string> kMalformed{
        "sha256:" + std::string(64, 'A'),
        "sha256:" + std::string(63, 'a'),
        "sha256:" + std::string(65, 'a'),
        std::string(64, 'a'),
        "sha512:" + std::string(64, 'a'),
        "",
        "sha256:" + std::string(62, 'a') + "..",
        "sha256:" + std::string(62, 'a') + "/x",
        "sha256:" + std::string(62, 'a') + "\\x",
        "/sha256:" + std::string(63, 'a'),
        "c:/" + std::string(68, 'a'),
        "//host/" + std::string(64, 'a'),
        "sha256:" + std::string(63, 'a') + "g",
        "sha256:" + std::string(63, 'a') + " ",
        std::string("sha256:") + std::string(63, 'a') + std::string(1, '\0'),
    };
    for (const std::string& kCandidate : kMalformed) {
        EXPECT_EQ(rejectionOfDigest(kCandidate), BlobRejection::InvalidDigest) << "candidate: " << kCandidate;
    }
}

TEST(BlobStore, RefusesToDeriveAPathFromAMalformedDigest) {
    const BlobStore kStore(std::filesystem::path("/store/blobs"));
    auto path = kStore.pathFor("sha256:../../../../../../etc/passwd" + std::string(31, 'a'));
    ASSERT_FALSE(path.has_value());
    EXPECT_EQ(path.error().rejection, BlobRejection::InvalidDigest);
}

// Verification item 6.
TEST(BlobStore, PutsIdenticalContentTwiceWithoutModifyingTheStoredFile) {
    const auto kFixture = fixture("idempotent");
    const BlobStore kStore = kFixture.store();
    auto first = kStore.put(kFixture.source);
    ASSERT_TRUE(first.has_value());
    auto path = kStore.pathFor(first->digest);
    ASSERT_TRUE(path.has_value());
    const auto kWrittenAt = std::filesystem::last_write_time(*path);

    auto second = kStore.put(kFixture.source);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->digest, first->digest);
    EXPECT_EQ(second->byteLength, first->byteLength);
    EXPECT_EQ(std::filesystem::last_write_time(*path), kWrittenAt) << "the stored blob must not be rewritten";
    EXPECT_EQ(readAllBytes(*path), kContent);
    EXPECT_EQ(countBlobShapedFiles(kFixture.blobsRoot), 1U);
}

// Verification item 7. The bytes are altered under the store, and every read
// path refuses them without touching them.
TEST(BlobStore, FailsClosedOnACorruptStoredBlobAndLeavesItUntouched) {
    const auto kFixture = fixture("corrupt");
    const BlobStore kStore = kFixture.store();
    ASSERT_TRUE(kStore.put(kFixture.source).has_value());
    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());
    writeFile(*path, R"({"a":2})");

    auto verified = kStore.verify(kContentDigest);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().rejection, BlobRejection::CorruptStoredBlob);

    auto fetched = kStore.get(kContentDigest);
    ASSERT_FALSE(fetched.has_value());
    EXPECT_EQ(fetched.error().rejection, BlobRejection::CorruptStoredBlob);

    auto republished = kStore.put(kFixture.source);
    ASSERT_FALSE(republished.has_value());
    EXPECT_EQ(republished.error().rejection, BlobRejection::CorruptStoredBlob);

    EXPECT_EQ(readAllBytes(*path), R"({"a":2})") << "the store never repairs, overwrites, or removes a blob";
}

TEST(BlobStore, RejectsAContentLengthThatDisagreesWithTheStoredBlob) {
    const auto kFixture = fixture("truncated");
    const BlobStore kStore = kFixture.store();
    ASSERT_TRUE(kStore.put(kFixture.source).has_value());
    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());
    writeFile(*path, kContent.substr(0, kContent.size() - 1U));
    auto verified = kStore.verify(kContentDigest);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().rejection, BlobRejection::CorruptStoredBlob);
}

// Verification item 8. Staging and publication are separate steps, so stopping
// between them is exactly what an interruption is.
TEST(BlobStore, LeavesNothingReachableWhenPublicationNeverRuns) {
    const auto kFixture = fixture("interrupted");
    const BlobStore kStore = kFixture.store();
    auto staged = kStore.stage(kFixture.source);
    ASSERT_TRUE(staged.has_value()) << (staged ? std::string{} : staged.error().detail);
    EXPECT_TRUE(std::filesystem::exists(staged->path));
    EXPECT_NE(staged->path.filename().string().size(), 62U) << "a staged name must never be blob shaped";

    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());
    EXPECT_FALSE(std::filesystem::exists(*path));

    auto verified = kStore.verify(kContentDigest);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().rejection, BlobRejection::MissingBlob);

    // The stray staged file stays where it is, and a later complete run still
    // succeeds and publishes exactly one blob.
    auto later = kStore.put(kFixture.source);
    ASSERT_TRUE(later.has_value());
    EXPECT_TRUE(std::filesystem::exists(staged->path)) << "no failure path removes a file it did not stage";
    EXPECT_EQ(countBlobShapedFiles(kFixture.blobsRoot), 1U);
    EXPECT_EQ(readAllBytes(*path), kContent);
}

TEST(BlobStore, DiscardsTheStagedFileOnceItIsPublished) {
    const auto kFixture = fixture("staged_cleanup");
    const BlobStore kStore = kFixture.store();
    auto staged = kStore.stage(kFixture.source);
    ASSERT_TRUE(staged.has_value());
    ASSERT_TRUE(kStore.publish(*staged).has_value());
    EXPECT_FALSE(std::filesystem::exists(staged->path));
}

// Verification item 9, source side.
TEST(BlobStore, RejectsASourceThatIsNotAnOrdinaryFile) {
    const auto kFixture = fixture("source_kind");
    const BlobStore kStore = kFixture.store();

    auto missing = kStore.put(kFixture.root / "absent.json");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().rejection, BlobRejection::SourceNotPermitted);

    auto directory = kStore.put(kFixture.root);
    ASSERT_FALSE(directory.has_value());
    EXPECT_EQ(directory.error().rejection, BlobRejection::SourceNotPermitted);
}

// A real reparse point, not a stand-in: a directory symbolic link where the
// host permits one and a junction on Windows, which needs no privilege.
//
// This is the half the store owns. Classification governs the final component,
// which is what every open on every host governs, so a link named as the source
// is refused rather than resolved and measured on the other side. A link in the
// middle of a path is a containment question rather than a kind question, and
// the case below holds that half.
TEST(BlobStore, RefusesAnIndirectSourceAsItsFinalComponent) {
    const auto kFixture = fixture("source_indirection");
    const BlobStore kStore = kFixture.store();
    const auto kTarget = kFixture.root / "target";
    std::filesystem::create_directories(kTarget);
    writeFile(kTarget / "content.json", kContent);

    const auto kLink = kFixture.root / "link";
    if (const std::string kFailure = createIndirection(kLink, kTarget); !kFailure.empty()) {
        GTEST_SKIP() << "this host cannot construct the subject: " << kFailure;
    }

    auto itself = kStore.put(kLink);
    ASSERT_FALSE(itself.has_value());
    EXPECT_EQ(itself.error().rejection, BlobRejection::SourceNotPermitted);
}

// The other half, at the authority that owns it. `--source` is resolved before
// the store ever sees it, and resolution is what refuses a path that leaves the
// repository through indirection it did not have to follow deliberately.
//
// The anchor is the same path without the escape: it resolves, so a rejection
// below is caused by where the link points rather than by resolution failing on
// anything it is handed.
TEST(BlobStore, RefusesASourcePathThatLeavesTheRepositoryThroughIndirection) {
    const auto kRoot = scratch("source_escape");
    const auto kRepository = kRoot / "repository";
    const auto kOutside = kRoot / "outside";
    std::filesystem::create_directories(kRepository / "inside");
    std::filesystem::create_directories(kOutside);
    writeFile(kRepository / "inside" / "content.json", kContent);
    writeFile(kOutside / "leak.json", kContent);

    auto admitted = resolveRepositoryPath(kRepository, "inside/content.json");
    ASSERT_TRUE(admitted.has_value()) << (admitted ? std::string{} : admitted.error().message);

    const auto kEscape = kRepository / "escape";
    if (const std::string kFailure = createIndirection(kEscape, kOutside); !kFailure.empty()) {
        GTEST_SKIP() << "this host cannot construct the subject: " << kFailure;
    }

    auto escaped = resolveRepositoryPath(kRepository, "escape/leak.json");
    ASSERT_FALSE(escaped.has_value()) << "content outside the repository was reachable through a link inside it";
    EXPECT_EQ(escaped.error().code, FailureCode::InvalidPath);
}

#ifndef _WIN32
// The two cases a file symbolic link creates, separated because they fail for
// different reasons if the classification ever regresses: one points at real
// content the store would otherwise happily copy, the other leaves the tree
// entirely.
TEST(BlobStore, RefusesAFileSymbolicLinkSourceWhereverItPoints) {
    const auto kFixture = fixture("source_symlink");
    const BlobStore kStore = kFixture.store();
    const auto kInside = writeFile(kFixture.root / "content.json", kContent);

    const auto kNear = kFixture.root / "near.json";
    std::filesystem::create_symlink(kInside, kNear);
    auto near = kStore.put(kNear);
    ASSERT_FALSE(near.has_value());
    EXPECT_EQ(near.error().rejection, BlobRejection::SourceNotPermitted);

    const auto kFar = kFixture.root / "far.json";
    std::filesystem::create_symlink("/etc/hostname", kFar);
    auto far = kStore.put(kFar);
    ASSERT_FALSE(far.has_value());
    EXPECT_EQ(far.error().rejection, BlobRejection::SourceNotPermitted);
}

TEST(BlobStore, RefusesAFifoSource) {
    const auto kFixture = fixture("source_fifo");
    const BlobStore kStore = kFixture.store();
    const auto kFifo = kFixture.root / "pipe";
    ASSERT_EQ(::mkfifo(kFifo.c_str(), S_IRUSR | S_IWUSR), 0);

    // A store that opened this would block forever on a source no writer is
    // ever going to fill, which is why the kind is checked before the read.
    auto result = kStore.put(kFifo);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().rejection, BlobRejection::SourceNotPermitted);
}
#endif

// Verification item 10, portable half: a bucket that is not a directory is
// refused on both the publication path and the read path. This reaches the same
// branch as the indirection case below and runs on every host, so the store's
// refusal is proven even where a link cannot be constructed.
TEST(BlobStore, RefusesAStoreDirectoryThatIsNotADirectory) {
    const auto kFixture = fixture("bucket_file");
    const BlobStore kStore = kFixture.store();
    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());
    writeFile(path->parent_path(), "not a directory");

    auto published = kStore.put(kFixture.source);
    ASSERT_FALSE(published.has_value());
    EXPECT_EQ(published.error().rejection, BlobRejection::UnsafePath);

    auto verified = kStore.verify(kContentDigest);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().rejection, BlobRejection::UnsafePath);
}

// Verification item 10. A bucket replaced by indirection is refused rather than
// traversed, on the read path and on the publication path alike. Windows
// symbolic links need a privilege an ordinary session does not hold, so this
// case runs on Linux; the Windows reparse classification it depends on is
// proven against a real junction in the file security suite.
TEST(BlobStore, RefusesAStoreDirectoryReplacedByIndirection) {
    const auto kFixture = fixture("bucket_indirection");
    const BlobStore kStore = kFixture.store();
    auto path = kStore.pathFor(kContentDigest);
    ASSERT_TRUE(path.has_value());

    const std::filesystem::path kBucket = path->parent_path();
    const std::filesystem::path kElsewhere = kFixture.root / "elsewhere";
    std::filesystem::create_directories(kElsewhere);
    std::filesystem::create_directories(kBucket.parent_path());

    // A junction where a symbolic link needs privilege, so this runs on both
    // hosts rather than proving the property on one of them.
    if (const std::string kFailure = createIndirection(kBucket, kElsewhere); !kFailure.empty()) {
        GTEST_SKIP() << "this host cannot construct the subject: " << kFailure;
    }

    auto published = kStore.put(kFixture.source);
    ASSERT_FALSE(published.has_value());
    EXPECT_EQ(published.error().rejection, BlobRejection::UnsafePath);

    auto verified = kStore.verify(kContentDigest);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().rejection, BlobRejection::UnsafePath);
}

TEST(BlobStore, ReportsAMissingBlobRatherThanCreatingItsBucket) {
    const auto kFixture = fixture("missing");
    const BlobStore kStore = kFixture.store();
    auto verified = kStore.verify(kContentDigest);
    ASSERT_FALSE(verified.has_value());
    EXPECT_EQ(verified.error().rejection, BlobRejection::MissingBlob);
    EXPECT_FALSE(std::filesystem::exists(kFixture.blobsRoot)) << "a read must not create the store";
}

// Verification item 11, at the boundary and one beyond it.
TEST(BlobStore, AdmitsContentAtTheByteCeilingAndRejectsOneBeyondIt) {
    {
        const auto kFixture = fixture("ceiling", std::string(kMaximumBlobBytes, 'r'));
        auto identity = kFixture.store().put(kFixture.source);
        ASSERT_TRUE(identity.has_value()) << (identity ? std::string{} : identity.error().detail);
        EXPECT_EQ(identity->byteLength, kMaximumBlobBytes);
    }
    {
        const auto kFixture = fixture("beyond", std::string(kMaximumBlobBytes + 1U, 'r'));
        const BlobStore kStore = kFixture.store();
        auto identity = kStore.put(kFixture.source);
        ASSERT_FALSE(identity.has_value());
        EXPECT_EQ(identity.error().rejection, BlobRejection::LimitExceeded);
        EXPECT_EQ(countBlobShapedFiles(kFixture.blobsRoot), 0U) << "a refused put leaves nothing behind";
    }
}

// Verification item 12: exact bytes, including the ones a text-mode stream
// would rewrite and the ones a string terminator would truncate.
TEST(BlobStore, ReturnsExactBytesIncludingControlAndHighBytes) {
    const std::string kAwkward{"line\r\nnext\0tail\x7f\xc3\xa9", 18U};
    const auto kFixture = fixture("exact_bytes", kAwkward);
    const BlobStore kStore = kFixture.store();
    auto identity = kStore.put(kFixture.source);
    ASSERT_TRUE(identity.has_value()) << (identity ? std::string{} : identity.error().detail);
    EXPECT_EQ(identity->byteLength, kAwkward.size());

    auto fetched = kStore.get(identity->digest);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(*fetched, kAwkward);
}

TEST(BlobStore, StoresAndReturnsEmptyContent) {
    const auto kFixture = fixture("empty", "");
    const BlobStore kStore = kFixture.store();
    auto identity = kStore.put(kFixture.source);
    ASSERT_TRUE(identity.has_value()) << (identity ? std::string{} : identity.error().detail);
    EXPECT_EQ(identity->byteLength, 0U);
    auto fetched = kStore.get(identity->digest);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_TRUE(fetched->empty());
}

TEST(BlobStore, ReportsTheSameDigestAsTheToolWideHash) {
    const auto kFixture = fixture("agreement");
    auto identity = kFixture.store().put(kFixture.source);
    ASSERT_TRUE(identity.has_value());
    auto direct = sha256Bytes(kContent);
    ASSERT_TRUE(direct.has_value());
    EXPECT_EQ(identity->digest, std::string(kDigestPrefix) + *direct);
}

TEST(BlobStore, RefusesToGetABlobThatWasNeverStored) {
    const auto kFixture = fixture("absent_get");
    const BlobStore kStore = kFixture.store();
    ASSERT_TRUE(kStore.put(kFixture.source).has_value());
    auto fetched = kStore.get("sha256:" + std::string(64, 'b'));
    ASSERT_FALSE(fetched.has_value());
    EXPECT_EQ(fetched.error().rejection, BlobRejection::MissingBlob);
}

// A staged copy that no longer matches the identity it was measured under is
// refused rather than published under the earlier digest. This is the window
// between the pass that names the blob and the pass that copies it.
TEST(BlobStore, RefusesToPublishAStagedCopyThatDisagreesWithItsMeasuredIdentity) {
    const auto kFixture = fixture("staged_mismatch");
    const BlobStore kStore = kFixture.store();
    auto staged = kStore.stage(kFixture.source);
    ASSERT_TRUE(staged.has_value());

    StagedBlob tampered = *staged;
    tampered.identity.digest = "sha256:" + std::string(64, 'c');
    auto published = kStore.publish(tampered);
    ASSERT_FALSE(published.has_value());
    EXPECT_EQ(published.error().rejection, BlobRejection::StagedVerificationFailed);

    // The genuine blob was never written, and the tampered digest named a path
    // that stays empty.
    EXPECT_EQ(countBlobShapedFiles(kFixture.blobsRoot), 0U);
}

} // namespace rawframe::tool::evidence
