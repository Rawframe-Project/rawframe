#include "record_command.h"

#include "blob_store.h"
#include "canonical_json.h"
#include "descriptor.h"
#include "evidence_set.h"
#include "file_reader.h"
#include "file_security.h"
#include "path_policy.h"
#include "raw_run_receipt.h"
#include "record_gate.h"

#include <filesystem>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <system_error>

namespace rawframe::tool::evidence {

namespace {

int failRecord(std::ostream& output, std::ostream& errors, const RecordFailure& failure, OutputFormat format) {
    if (format == OutputFormat::Json) {
        output << buildRejectionOutput(failure);
    }
    renderFailure(errors,
                  Failure{FailureCode::VerificationFailed, recordRejectionName(failure.rejection), failure.detail},
                  format);
    return 3;
}

// Shared by both record operations: a record is always read through the record
// byte ceiling rather than the maintained-JSON one, because these bytes are
// untrusted input and not a manifest this repository maintains.
Result<std::string> readRecordBytes(const std::filesystem::path& path) {
    auto input = readBoundedFile(path, kMaximumRecordBytes);
    if (!input) {
        return std::unexpected(input.error());
    }
    return std::string(std::string_view(input->data(), input->size()));
}

Result<std::filesystem::path>
resolveRecordArgument(const ParsedOptions& options, const std::optional<std::string>& argument, std::string_view flag) {
    if (!argument) {
        return std::unexpected(Failure{FailureCode::InvalidArguments, std::string(flag), "a record path is required"});
    }
    std::filesystem::path candidate(*argument);
    if (candidate.is_relative()) {
        candidate = options.repositoryRoot / candidate;
    }
    std::error_code error;
    auto resolved = std::filesystem::weakly_canonical(candidate, error);
    if (error) {
        return std::unexpected(Failure{FailureCode::InvalidPath, *argument, "failed to resolve the path"});
    }
    return resolved;
}

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

BlobStore storeFor(const ParsedOptions& options) {
    return BlobStore(options.repositoryRoot / std::filesystem::path(kBlobStoreRelativeRoot));
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

// Decision 1: the kind is read from the record's own bytes. A caller never
// supplies it, so no command line can relabel a record on its way past. Each
// kind carries its own media type and its own gate; nothing here is a default.
struct RecordKindBinding {
    std::string_view mediaType;
};

RecordResult<RecordKindBinding> bindRecordKind(const CanonicalValue& record) {
    auto kind = readRecordKind(record);
    if (!kind) {
        return std::unexpected(kind.error());
    }
    if (*kind == kRawRunReceiptRecordKind) {
        return RecordKindBinding{kRawRunReceiptMediaType};
    }
    if (*kind == kEvidenceSetRecordKind) {
        return RecordKindBinding{kEvidenceSetMediaType};
    }
    if (*kind == kAttemptPlanRecordKind) {
        return RecordKindBinding{kAttemptPlanMediaType};
    }
    return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "record declares an unknown kind: " + *kind});
}

// The semantic gate for whichever kind the record declared. A receipt is
// summarized; the other kinds are gated and reported by identity, because
// neither has a summary that means anything a caller would act on.
RecordResult<std::string> gateRecord(const std::filesystem::path& repositoryRoot,
                                     const std::filesystem::path& instancePath,
                                     const CanonicalValue& record,
                                     std::string_view mediaType) {
    if (mediaType == kRawRunReceiptMediaType) {
        auto summary = validateRawRunReceipt(repositoryRoot, instancePath, record, mediaType);
        if (!summary) {
            return std::unexpected(summary.error());
        }
        return summary->runId;
    }
    if (auto status = checkProducerAuthority(record); !status) {
        return std::unexpected(status.error());
    }
    if (mediaType == kAttemptPlanMediaType) {
        auto plan = parseAttemptPlan(repositoryRoot, instancePath, record);
        if (!plan) {
            return std::unexpected(plan.error());
        }
        if (auto status = checkGenerationMatches(record, mediaType, kAttemptPlanGeneration); !status) {
            return std::unexpected(status.error());
        }
        return plan->planId;
    }
    if (auto status = checkRecordKind(record, kEvidenceSetRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(repositoryRoot, kEvidenceSetSchemaPath, instancePath); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationMatches(record, mediaType, kEvidenceSetGeneration); !status) {
        return std::unexpected(status.error());
    }
    const auto* kIdentity = record.find("evidenceSetId");
    if (kIdentity == nullptr || kIdentity->kind() != CanonicalValue::Kind::String) {
        return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "evidence set carries no identity"});
    }
    return kIdentity->text();
}

int emitDescriptor(std::ostream& output, const Descriptor& descriptor) {
    output << serializeCanonical(describeAsValue(descriptor));
    return 0;
}

} // namespace

int fail(std::ostream& errors, const Failure& failure, OutputFormat format) {
    renderFailure(errors, failure, format);
    return failure.code == FailureCode::InvalidArguments ? 2 : 3;
}

int canonicalizeOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto recordPath = resolveRecordArgument(options, options.recordPath, "--record");
    if (!recordPath) {
        return fail(errors, recordPath.error(), options.format);
    }
    auto bytes = readRecordBytes(*recordPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    // Authored input, so it is parsed rather than ingested: it is not required
    // to already be canonical, which is the whole point of this operation.
    auto parsed = parseCanonicalSubset(*bytes);
    if (!parsed) {
        return failRecord(output, errors, parsed.error(), options.format);
    }
    const std::string kCanonical = serializeCanonical(*parsed);
    auto binding = bindRecordKind(*parsed);
    if (!binding) {
        return failRecord(output, errors, binding.error(), options.format);
    }
    auto descriptor = describeBytes(kCanonical, binding->mediaType);
    if (!descriptor) {
        return failRecord(output, errors, descriptor.error(), options.format);
    }
    auto identity = gateRecord(options.repositoryRoot, *recordPath, *parsed, descriptor->mediaType);
    if (!identity) {
        return failRecord(output, errors, identity.error(), options.format);
    }
    if (options.format == OutputFormat::Json) {
        if (binding->mediaType == kRawRunReceiptMediaType) {
            auto summary = summarizeRawRunReceipt(*parsed);
            if (!summary) {
                return failRecord(output, errors, summary.error(), options.format);
            }
            output << buildCanonicalizeOutput(*descriptor, *summary);
            return 0;
        }
        output << serializeCanonical(describeAsValue(*descriptor));
        return 0;
    }
    // The bytes themselves, exactly, with nothing appended. A trailing newline
    // here would be a byte this repository's canonical form does not have.
    output << kCanonical;
    return 0;
}

int validateRecordOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto recordPath = resolveRecordArgument(options, options.recordPath, "--record");
    if (!recordPath) {
        return fail(errors, recordPath.error(), options.format);
    }
    auto bytes = readRecordBytes(*recordPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    auto record = ingestCanonicalBytes(*bytes);
    if (!record) {
        return failRecord(output, errors, record.error(), options.format);
    }

    auto binding = bindRecordKind(*record);
    if (!binding) {
        return failRecord(output, errors, binding.error(), options.format);
    }
    const std::string_view kMediaType = binding->mediaType;

    Descriptor descriptor{std::string(kMediaType), bytes->size(), {}};
    if (options.descriptorPath) {
        auto descriptorPath = resolveRecordArgument(options, options.descriptorPath, "--descriptor");
        if (!descriptorPath) {
            return fail(errors, descriptorPath.error(), options.format);
        }
        auto descriptorBytes = readRecordBytes(*descriptorPath);
        if (!descriptorBytes) {
            return fail(errors, descriptorBytes.error(), options.format);
        }
        auto descriptorValue = ingestCanonicalBytes(*descriptorBytes);
        if (!descriptorValue) {
            return failRecord(output, errors, descriptorValue.error(), options.format);
        }
        auto supplied = parseDescriptor(*descriptorValue);
        if (!supplied) {
            return failRecord(output, errors, supplied.error(), options.format);
        }
        if (auto status = verifyDescriptor(*supplied, *bytes, kMediaType); !status) {
            return failRecord(output, errors, status.error(), options.format);
        }
        descriptor = *supplied;
    } else {
        auto computed = describeBytes(*bytes, kMediaType);
        if (!computed) {
            return failRecord(output, errors, computed.error(), options.format);
        }
        descriptor = *computed;
    }

    auto identity = gateRecord(options.repositoryRoot, *recordPath, *record, descriptor.mediaType);
    if (!identity) {
        return failRecord(output, errors, identity.error(), options.format);
    }
    if (options.format == OutputFormat::Json) {
        if (kMediaType == kRawRunReceiptMediaType) {
            auto summary = summarizeRawRunReceipt(*record);
            if (!summary) {
                return failRecord(output, errors, summary.error(), options.format);
            }
            output << buildValidateOutput(descriptor, *summary);
            return 0;
        }
        output << serializeCanonical(describeAsValue(descriptor));
        return 0;
    }
    renderSuccess(output, "validate_record", *identity + " is canonical and valid", options.format);
    return 0;
}

// Assembly reads a declared plan, retrieves each named receipt from the store,
// and emits one ledger. It writes nothing: the bytes go to standard output and
// a caller stores them with `put blob`, which keeps the thing that produces
// evidence separate from the thing that holds it.
int assembleOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto planPath = resolveRecordArgument(options, options.planPath, "--plan");
    if (!planPath) {
        return fail(errors, planPath.error(), options.format);
    }
    auto bytes = readRecordBytes(*planPath);
    if (!bytes) {
        return fail(errors, bytes.error(), options.format);
    }
    auto plan = ingestCanonicalBytes(*bytes);
    if (!plan) {
        return failRecord(output, errors, plan.error(), options.format);
    }
    auto parsed = parseAttemptPlan(options.repositoryRoot, *planPath, *plan);
    if (!parsed) {
        return failRecord(output, errors, parsed.error(), options.format);
    }
    // The set's own identity is supplied rather than derived. Deriving it from
    // the content would make two assemblies of the same schedule the same
    // record, which they are not: they are two assemblies.
    if (!options.setId) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments, "--set-id", "an evidence set identity is required"},
                    options.format);
    }
    const BlobStore kStore = storeFor(options);
    auto assembled = assembleEvidenceSet(kStore, *parsed, *options.setId);
    if (!assembled) {
        return failRecord(output, errors, assembled.error(), options.format);
    }
    output << serializeCanonical(*assembled);
    return 0;
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
