#pragma once

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

// Why a store operation refused. These live with the store rather than in the
// tool-wide failure list for the same reason record rejections live with the
// record: a caller that handles them is reasoning about content addressing, not
// about the tool.
enum class BlobRejection : std::uint8_t {
    InvalidDigest,
    SourceNotPermitted,
    UnsafePath,
    LimitExceeded,
    StagingCollision,
    StagedVerificationFailed,
    CorruptStoredBlob,
    MissingBlob,
    StoreIoFailure,
};

[[nodiscard]] constexpr const char* blobRejectionName(BlobRejection rejection) noexcept {
    switch (rejection) {
    case BlobRejection::InvalidDigest:
        return "invalid_digest";
    case BlobRejection::SourceNotPermitted:
        return "source_not_permitted";
    case BlobRejection::UnsafePath:
        return "unsafe_path";
    case BlobRejection::LimitExceeded:
        return "limit_exceeded";
    case BlobRejection::StagingCollision:
        return "staging_collision";
    case BlobRejection::StagedVerificationFailed:
        return "staged_verification_failed";
    case BlobRejection::CorruptStoredBlob:
        return "corrupt_stored_blob";
    case BlobRejection::MissingBlob:
        return "missing_blob";
    case BlobRejection::StoreIoFailure:
        return "store_io_failure";
    }
    return "unknown_blob_rejection";
}

struct BlobFailure {
    BlobRejection rejection;
    std::string subject;
    std::string detail;
};

template <typename ValueType> using BlobResult = std::expected<ValueType, BlobFailure>;
using BlobStatus = BlobResult<void>;

// The store's finite limits, fixed by the accepted TASK-0003 packet. Each fails
// closed and none of them yields a partial result.
//
// Sixteen times the one-mebibyte canonical record ceiling. The local store
// holds records and their small immediate fixtures; ADR-0019 places large raw
// samples, traces, and logs in external content-addressed storage.
inline constexpr std::uint64_t kMaximumBlobBytes = 16'777'216;
inline constexpr unsigned kStagingCollisionRetries = 4;

inline constexpr std::string_view kDigestPrefix = "sha256:";
inline constexpr std::size_t kDigestHexLength = 64;
inline constexpr std::size_t kDigestTextLength = 71;
inline constexpr std::size_t kBucketNameLength = 2;

// The store lives at exactly the path SPEC-0017 requires, relative to the
// repository root. There is no option and no environment variable: a
// configurable store root is where an evidence tool acquires ambient authority
// over where evidence lives, and nothing needs it.
inline constexpr std::string_view kBlobStoreRelativeRoot = "out/evidence/v1/blobs";

// What the store knows about content: its exact length and its digest. The
// media type is not here, because a store that understood what its bytes mean
// would be a second validation authority. Callers carry the media type through
// and place it in the descriptor at their own boundary.
struct BlobIdentity {
    std::uint64_t byteLength = 0;
    // The full `sha256:<64 lowercase hex>` form, matching Descriptor::digest.
    std::string digest;
};

struct StagedBlob {
    std::filesystem::path path;
    BlobIdentity identity;
};

// Accepts exactly `sha256:` followed by sixty-four lowercase hexadecimal
// characters. Everything a derived path could be attacked with, a traversal
// sequence, an absolute prefix, a drive letter, a separator of either slope,
// a case variant, is outside that alphabet, so the store's path safety is a
// property of this function rather than of a filter applied later.
[[nodiscard]] BlobStatus validateBlobDigest(std::string_view digest);

class BlobStore {
public:
    // The absolute path of the `blobs` directory, which the command layer
    // derives from the repository root and tests point at scratch space.
    explicit BlobStore(std::filesystem::path blobsRoot);

    [[nodiscard]] const std::filesystem::path& root() const noexcept;

    [[nodiscard]] BlobResult<std::filesystem::path> pathFor(std::string_view digest) const;

    // Measures the source, then writes a copy of it next to where the blob will
    // live. Nothing is published: an interruption is exactly a run that stops
    // between this and publish, and what it leaves behind is a file whose name
    // can never be reached by a path derived from a digest.
    [[nodiscard]] BlobResult<StagedBlob> stage(const std::filesystem::path& source) const;

    // Reverifies the staged bytes against the identity they claim, then moves
    // them onto the final path without replacement. If the destination already
    // holds the same content the staged copy is discarded and the existing blob
    // is verified rather than rewritten.
    [[nodiscard]] BlobResult<BlobIdentity> publish(const StagedBlob& staged) const;

    // stage followed by publish. Idempotent: putting identical content twice
    // returns the identical identity and does not modify the stored file.
    [[nodiscard]] BlobResult<BlobIdentity> put(const std::filesystem::path& source) const;

    [[nodiscard]] BlobResult<BlobIdentity> verify(std::string_view digest) const;

    // The bytes, after their length and digest have both been reverified.
    [[nodiscard]] BlobResult<std::string> get(std::string_view digest) const;

private:
    std::filesystem::path blobsRoot_;
};

} // namespace rawframe::tool::evidence
