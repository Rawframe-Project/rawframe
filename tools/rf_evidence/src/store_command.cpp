#include "store_command.h"

#include "canonical_json.h"
#include "descriptor.h"
#include "file_security.h"
#include "path_policy.h"

#include <filesystem>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>

namespace rawframe::tool::evidence {

namespace {

int failBlob(std::ostream& output, std::ostream& errors, const BlobFailure& failure, OutputFormat format) {
    if (format == OutputFormat::Json) {
        std::ostringstream json;
        json << R"({"rejection":)";
        writeJsonString(json, blobRejectionName(failure.rejection));
        json << R"(,"subject":)";
        writeJsonString(json, failure.subject);
        json << R"(,"detail":)";
        writeJsonString(json, failure.detail);
        json << "}";
        output << json.str();
    }
    renderFailure(
        errors, Failure{FailureCode::VerificationFailed, blobRejectionName(failure.rejection), failure.detail}, format);
    return 3;
}

// The store computes length and digest; the media type is the caller's
// declaration of what contract the content was produced under, which no amount
// of reading the bytes reveals. The two meet here, at the command boundary,
// rather than inside a store that would otherwise have to understand its
// contents to hold them.
Result<Descriptor> describeStoredBlob(const BlobIdentity& identity, const std::optional<std::string>& mediaType) {
    if (!mediaType) {
        return std::unexpected(Failure{FailureCode::InvalidArguments, "--media", "a media type is required"});
    }
    return Descriptor{*mediaType, identity.byteLength, identity.digest};
}

// Repository-relative, and classified before it is used. `resolveRepositoryPath`
// rejects absolute paths, backslashes, traversal, overlong components, and
// anything resolving outside the repository, but it resolves through
// weakly_canonical, which follows links. So the unresolved join is classified
// too: a symbolic link or junction planted at the source name is refused rather
// than silently read through.
Result<std::filesystem::path> resolveContentSource(const ParsedOptions& options) {
    if (!options.sourcePath) {
        return std::unexpected(
            Failure{FailureCode::InvalidArguments, "--source", "a repository-relative content path is required"});
    }
    auto resolved = resolveRepositoryPath(options.repositoryRoot, *options.sourcePath);
    if (!resolved) {
        return std::unexpected(resolved.error());
    }
    const std::filesystem::path kJoined = options.repositoryRoot / std::filesystem::path(*options.sourcePath);
    auto kind = classifyPath(kJoined);
    if (!kind) {
        return std::unexpected(kind.error());
    }
    if (*kind != FileKind::Regular) {
        return std::unexpected(Failure{
            FailureCode::InvalidPath, *options.sourcePath, std::string("the source is a ") + fileKindName(*kind)});
    }
    return resolved;
}

int emitDescriptor(std::ostream& output, const Descriptor& descriptor) {
    output << serializeCanonical(describeAsValue(descriptor));
    return 0;
}

} // namespace

BlobStore storeFor(const ParsedOptions& options) {
    return BlobStore(options.repositoryRoot / std::filesystem::path(kBlobStoreRelativeRoot));
}

int putBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto source = resolveContentSource(options);
    if (!source) {
        return fail(errors, source.error(), options.format);
    }
    const BlobStore kStore = storeFor(options);
    auto identity = kStore.put(*source);
    if (!identity) {
        return failBlob(output, errors, identity.error(), options.format);
    }
    auto descriptor = describeStoredBlob(*identity, options.mediaType);
    if (!descriptor) {
        return fail(errors, descriptor.error(), options.format);
    }
    return emitDescriptor(output, *descriptor);
}

int verifyBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    if (!options.digest) {
        return fail(
            errors, Failure{FailureCode::InvalidArguments, "--digest", "a content digest is required"}, options.format);
    }
    const BlobStore kStore = storeFor(options);
    auto identity = kStore.verify(*options.digest);
    if (!identity) {
        return failBlob(output, errors, identity.error(), options.format);
    }
    auto descriptor = describeStoredBlob(*identity, options.mediaType);
    if (!descriptor) {
        return fail(errors, descriptor.error(), options.format);
    }
    return emitDescriptor(output, *descriptor);
}

int getBlobOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    if (!options.digest) {
        return fail(
            errors, Failure{FailureCode::InvalidArguments, "--digest", "a content digest is required"}, options.format);
    }
    const BlobStore kStore = storeFor(options);
    auto bytes = kStore.get(*options.digest);
    if (!bytes) {
        return failBlob(output, errors, bytes.error(), options.format);
    }
    // The bytes themselves, exactly, with nothing appended and nothing
    // translated. Standard output is put in binary mode before this runs.
    output.write(bytes->data(), static_cast<std::streamsize>(bytes->size()));
    return 0;
}

} // namespace rawframe::tool::evidence
