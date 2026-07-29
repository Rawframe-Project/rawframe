#include "blob_store.h"

#include "file_security.h"
#include "sha256.h"

#include <atomic>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

namespace rawframe::tool::evidence {

namespace {

BlobFailure reject(BlobRejection rejection, std::string subject, std::string detail) {
    return BlobFailure{rejection, std::move(subject), std::move(detail)};
}

// A tool-wide Failure carries no store vocabulary, so every one that crosses
// into the store is mapped explicitly rather than flattened into one code.
BlobFailure fromFailure(const Failure& failure, BlobRejection rejection) {
    return BlobFailure{rejection, failure.path, failure.message};
}

bool isLowercaseHex(char character) {
    return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
}

// Unique without consulting a clock, matching the capture-directory idiom the
// process runner already uses.
std::string stagingSuffix(unsigned attempt) {
    static std::atomic<unsigned long long> stagings{0};
#ifdef _WIN32
    const auto kProcess = static_cast<unsigned long long>(GetCurrentProcessId());
#else
    const auto kProcess = static_cast<unsigned long long>(getpid());
#endif
    const auto kOrdinal = stagings.fetch_add(1U);
    return "." + std::to_string(kProcess) + "." + std::to_string(kOrdinal) + "." + std::to_string(attempt) + ".tmp";
}

// Streams a file, enforcing the byte ceiling as it goes rather than after, and
// returns the identity of what it read. Used for the source, for the staged
// copy, and for an existing destination, so all three are measured the same way.
BlobResult<BlobIdentity> measureFile(const std::filesystem::path& path) {
    const std::string kSubject = path.generic_string();

    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return std::unexpected(reject(BlobRejection::StoreIoFailure, kSubject, "failed to open the content"));
    }

    Sha256Stream digest(kSubject);
    if (auto status = digest.begin(); !status) {
        return std::unexpected(fromFailure(status.error(), BlobRejection::StoreIoFailure));
    }

    std::vector<char> buffer(kSha256ChunkBytes);
    std::uint64_t total = 0;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto kCount = input.gcount();
        if (kCount <= 0) {
            continue;
        }
        total += static_cast<std::uint64_t>(kCount);
        if (total > kMaximumBlobBytes) {
            return std::unexpected(
                reject(BlobRejection::LimitExceeded,
                       kSubject,
                       "content exceeds the " + std::to_string(kMaximumBlobBytes) + " byte blob ceiling"));
        }
        const std::string_view kChunk{buffer.data(), static_cast<std::size_t>(kCount)};
        if (auto status = digest.update(kChunk); !status) {
            return std::unexpected(fromFailure(status.error(), BlobRejection::StoreIoFailure));
        }
    }
    if (!input.eof()) {
        return std::unexpected(reject(BlobRejection::StoreIoFailure, kSubject, "failed while reading the content"));
    }

    auto hex = digest.finish();
    if (!hex) {
        return std::unexpected(fromFailure(hex.error(), BlobRejection::StoreIoFailure));
    }
    return BlobIdentity{total, std::string(kDigestPrefix) + *hex};
}

// Best effort, and only ever the path this operation created itself. No failure
// path scans the store or removes a file it did not stage.
void discardStaged(const std::filesystem::path& staged) {
    std::error_code error;
    std::filesystem::remove(staged, error);
}

} // namespace

BlobStatus validateBlobDigest(std::string_view digest) {
    const std::string kSubject{digest};
    if (digest.size() != kDigestTextLength) {
        return std::unexpected(reject(BlobRejection::InvalidDigest,
                                      kSubject,
                                      "a digest is exactly " + std::to_string(kDigestTextLength) + " characters"));
    }
    if (!digest.starts_with(kDigestPrefix)) {
        return std::unexpected(
            reject(BlobRejection::InvalidDigest, kSubject, "the digest carries no sha256: algorithm prefix"));
    }
    const std::string_view kHex = digest.substr(kDigestPrefix.size());
    for (const char kCharacter : kHex) {
        if (!isLowercaseHex(kCharacter)) {
            return std::unexpected(reject(BlobRejection::InvalidDigest,
                                          kSubject,
                                          "the digest is not sixty-four lowercase hexadecimal characters"));
        }
    }
    return {};
}

BlobStore::BlobStore(std::filesystem::path blobsRoot) : blobsRoot_(std::move(blobsRoot)) {
}

const std::filesystem::path& BlobStore::root() const noexcept {
    return blobsRoot_;
}

BlobResult<std::filesystem::path> BlobStore::pathFor(std::string_view digest) const {
    if (auto status = validateBlobDigest(digest); !status) {
        return std::unexpected(status.error());
    }
    const std::string_view kHex = digest.substr(kDigestPrefix.size());
    const std::string kBucket{kHex.substr(0, kBucketNameLength)};
    const std::string kLeaf{kHex.substr(kBucketNameLength)};
    return blobsRoot_ / "sha256" / kBucket / kLeaf;
}

namespace {

// Every directory on the way to a blob is classified without following
// indirection, so a bucket replaced by a junction pointing outside the store is
// refused rather than traversed. `create` is false on read paths: a missing
// directory there means the blob is missing, not that one should be made.
BlobStatus walkStoreChain(const std::filesystem::path& blobPath, bool create) {
    const std::filesystem::path kBucket = blobPath.parent_path();
    const std::filesystem::path kAlgorithm = kBucket.parent_path();
    const std::filesystem::path kRoot = kAlgorithm.parent_path();

    for (const std::filesystem::path& kDirectory : {kRoot, kAlgorithm, kBucket}) {
        auto kind = classifyPath(kDirectory);
        if (!kind) {
            return std::unexpected(fromFailure(kind.error(), BlobRejection::StoreIoFailure));
        }
        switch (*kind) {
        case FileKind::Directory:
            break;
        case FileKind::Missing: {
            if (!create) {
                return std::unexpected(
                    reject(BlobRejection::MissingBlob, kDirectory.generic_string(), "the store has no such bucket"));
            }
            std::error_code error;
            // Recursive, because the store root's own ancestors under `out/`
            // may not exist yet on a clean tree. The three levels that matter
            // are classified above; everything above them is the repository's
            // own build output, at the same trust level as the root itself.
            std::filesystem::create_directories(kDirectory, error);
            if (error && !std::filesystem::is_directory(kDirectory)) {
                return std::unexpected(
                    reject(BlobRejection::StoreIoFailure, kDirectory.generic_string(), error.message()));
            }
            break;
        }
        default:
            return std::unexpected(reject(BlobRejection::UnsafePath,
                                          kDirectory.generic_string(),
                                          std::string("the store path is a ") + fileKindName(*kind)));
        }
    }
    return {};
}

// Reads back what is on disk and proves it is exactly what the caller expects,
// in both length and digest. Used for a staged copy and for an existing
// destination, because both questions are the same question.
BlobStatus
confirmStoredContent(const std::filesystem::path& path, const BlobIdentity& expected, BlobRejection rejection) {
    auto observed = measureFile(path);
    if (!observed) {
        return std::unexpected(observed.error());
    }
    if (observed->byteLength != expected.byteLength) {
        return std::unexpected(reject(rejection,
                                      path.generic_string(),
                                      "stored byte length " + std::to_string(observed->byteLength) +
                                          " disagrees with " + std::to_string(expected.byteLength)));
    }
    if (observed->digest != expected.digest) {
        return std::unexpected(
            reject(rejection, path.generic_string(), "stored digest disagrees with " + expected.digest));
    }
    return {};
}

} // namespace

BlobResult<StagedBlob> BlobStore::stage(const std::filesystem::path& source) const {
    const std::string kSubject = source.generic_string();

    auto kind = classifyPath(source);
    if (!kind) {
        return std::unexpected(fromFailure(kind.error(), BlobRejection::StoreIoFailure));
    }
    if (*kind != FileKind::Regular) {
        return std::unexpected(
            reject(BlobRejection::SourceNotPermitted, kSubject, std::string("the source is a ") + fileKindName(*kind)));
    }

    // Pass one names the blob. The destination path cannot be known before the
    // digest is, so the copy below cannot compute it on the way through.
    auto identity = measureFile(source);
    if (!identity) {
        return std::unexpected(identity.error());
    }

    auto destination = pathFor(identity->digest);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    if (auto status = walkStoreChain(*destination, true); !status) {
        return std::unexpected(status.error());
    }

    // Pass two copies, and publish runs pass three over the result before it
    // moves anything. The staged name carries a suffix, so it is never the
    // sixty-two hexadecimal characters a derived path looks for, whatever
    // happens to this process before publication.
    std::filesystem::path staged;
    ExclusiveFile file;
    for (unsigned attempt = 0; attempt <= kStagingCollisionRetries; ++attempt) {
        staged = *destination;
        staged += stagingSuffix(attempt);
        auto created = file.create(staged);
        if (created) {
            break;
        }
        if (created.error().code != FailureCode::OwnershipCollision) {
            return std::unexpected(fromFailure(created.error(), BlobRejection::StoreIoFailure));
        }
        if (attempt == kStagingCollisionRetries) {
            return std::unexpected(
                reject(BlobRejection::StagingCollision,
                       staged.generic_string(),
                       "no unused staging name after " + std::to_string(kStagingCollisionRetries + 1U) + " attempts"));
        }
    }

    {
        std::ifstream input(source, std::ios::binary);
        if (!input) {
            discardStaged(staged);
            return std::unexpected(reject(BlobRejection::StoreIoFailure, kSubject, "failed to reopen the source"));
        }
        std::vector<char> buffer(kSha256ChunkBytes);
        while (input) {
            input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const auto kCount = input.gcount();
            if (kCount <= 0) {
                continue;
            }
            const std::string_view kChunk{buffer.data(), static_cast<std::size_t>(kCount)};
            if (auto status = file.write(kChunk); !status) {
                discardStaged(staged);
                return std::unexpected(fromFailure(status.error(), BlobRejection::StoreIoFailure));
            }
        }
        if (!input.eof()) {
            discardStaged(staged);
            return std::unexpected(reject(BlobRejection::StoreIoFailure, kSubject, "failed while reading the source"));
        }
    }

    if (auto status = file.close(); !status) {
        discardStaged(staged);
        return std::unexpected(fromFailure(status.error(), BlobRejection::StoreIoFailure));
    }

    return StagedBlob{staged, *identity};
}

BlobResult<BlobIdentity> BlobStore::publish(const StagedBlob& staged) const {
    // Pass three, immediately before the move, proves the bytes on disk are the
    // bytes the identity names. It closes two windows at once: a write that did
    // not land whole, and a source edited between the pass that named the blob
    // and the pass that copied it. Either way the staged copy no longer matches
    // its own name and is refused rather than published under it.
    if (auto status = confirmStoredContent(staged.path, staged.identity, BlobRejection::StagedVerificationFailed);
        !status) {
        discardStaged(staged.path);
        return std::unexpected(status.error());
    }

    auto destination = pathFor(staged.identity.digest);
    if (!destination) {
        discardStaged(staged.path);
        return std::unexpected(destination.error());
    }

    auto kind = classifyPath(*destination);
    if (!kind) {
        discardStaged(staged.path);
        return std::unexpected(fromFailure(kind.error(), BlobRejection::StoreIoFailure));
    }

    if (*kind == FileKind::Missing) {
        auto moved = publishWithoutReplacement(staged.path, *destination);
        if (moved) {
            return staged.identity;
        }
        if (moved.error().code != FailureCode::OwnershipCollision) {
            discardStaged(staged.path);
            return std::unexpected(fromFailure(moved.error(), BlobRejection::StoreIoFailure));
        }
        // Another process published the same content between the classification
        // above and the move. That is not a conflict: the content is identical
        // by construction, so it is verified on the path below like any other
        // existing destination.
        kind = classifyPath(*destination);
        if (!kind) {
            discardStaged(staged.path);
            return std::unexpected(fromFailure(kind.error(), BlobRejection::StoreIoFailure));
        }
    }

    discardStaged(staged.path);

    if (*kind != FileKind::Regular) {
        return std::unexpected(reject(BlobRejection::UnsafePath,
                                      destination->generic_string(),
                                      std::string("the destination is a ") + fileKindName(*kind)));
    }

    // The destination already exists. It is verified and left exactly as it is:
    // the store never repairs, overwrites, quarantines, or removes a blob,
    // because deciding what to do about corrupted evidence is not a mechanical
    // operation.
    if (auto status = confirmStoredContent(*destination, staged.identity, BlobRejection::CorruptStoredBlob); !status) {
        return std::unexpected(status.error());
    }
    return staged.identity;
}

BlobResult<BlobIdentity> BlobStore::put(const std::filesystem::path& source) const {
    auto staged = stage(source);
    if (!staged) {
        return std::unexpected(staged.error());
    }
    return publish(*staged);
}

BlobResult<BlobIdentity> BlobStore::verify(std::string_view digest) const {
    auto path = pathFor(digest);
    if (!path) {
        return std::unexpected(path.error());
    }
    if (auto status = walkStoreChain(*path, false); !status) {
        return std::unexpected(status.error());
    }

    auto kind = classifyPath(*path);
    if (!kind) {
        return std::unexpected(fromFailure(kind.error(), BlobRejection::StoreIoFailure));
    }
    if (*kind == FileKind::Missing) {
        return std::unexpected(
            reject(BlobRejection::MissingBlob, path->generic_string(), "the store holds no such blob"));
    }
    if (*kind != FileKind::Regular) {
        return std::unexpected(reject(BlobRejection::UnsafePath,
                                      path->generic_string(),
                                      std::string("the stored path is a ") + fileKindName(*kind)));
    }

    auto observed = measureFile(*path);
    if (!observed) {
        return std::unexpected(observed.error());
    }
    if (observed->digest != std::string(digest)) {
        return std::unexpected(
            reject(BlobRejection::CorruptStoredBlob,
                   path->generic_string(),
                   "stored bytes hash to " + observed->digest + " rather than " + std::string(digest)));
    }
    return *observed;
}

BlobResult<std::string> BlobStore::get(std::string_view digest) const {
    // Verification first, always. Bytes are returned only after both their
    // length and their digest have been proven against the name they were
    // asked for.
    auto identity = verify(digest);
    if (!identity) {
        return std::unexpected(identity.error());
    }

    auto path = pathFor(digest);
    if (!path) {
        return std::unexpected(path.error());
    }

    std::ifstream input(*path, std::ios::binary);
    if (!input) {
        return std::unexpected(
            reject(BlobRejection::StoreIoFailure, path->generic_string(), "failed to open the blob"));
    }
    std::string bytes;
    bytes.resize(static_cast<std::size_t>(identity->byteLength));
    if (identity->byteLength > 0) {
        input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (static_cast<std::uint64_t>(input.gcount()) != identity->byteLength) {
            return std::unexpected(reject(BlobRejection::CorruptStoredBlob,
                                          path->generic_string(),
                                          "the blob changed length between verification and read"));
        }
    }

    auto reread = sha256Bytes(bytes);
    if (!reread) {
        return std::unexpected(fromFailure(reread.error(), BlobRejection::StoreIoFailure));
    }
    if (std::string(kDigestPrefix) + *reread != identity->digest) {
        return std::unexpected(reject(BlobRejection::CorruptStoredBlob,
                                      path->generic_string(),
                                      "the blob changed between verification and read"));
    }
    return bytes;
}

} // namespace rawframe::tool::evidence
