#include "command.h"

#include "blob_store.h"
#include "canonical_json.h"
#include "descriptor.h"
#include "diagnostic.h"
#include "file_reader.h"
#include "file_security.h"
#include "license_review.h"
#include "offline_verifier.h"
#include "path_audit.h"
#include "path_policy.h"
#include "raw_run_receipt.h"
#include "report_writer.h"
#include "repository_validator.h"
#include "shipping_closure.h"
#include "source_inspector.h"

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <system_error>

namespace rawframe::tool::evidence {

namespace {

struct ParsedOptions {
    std::filesystem::path repositoryRoot;
    std::optional<std::string> toolId;
    std::optional<std::string> hostId;
    std::optional<std::string> reportPath;
    std::optional<std::string> recordPath;
    std::optional<std::string> descriptorPath;
    std::optional<std::string> sourcePath;
    std::optional<std::string> digest;
    std::optional<std::string> mediaType;
    OutputFormat format = OutputFormat::Human;
};

Result<ParsedOptions> parseOptions(std::span<const std::string_view> arguments) {
    ParsedOptions options;
    bool hasRoot = false;
    for (auto current = arguments.begin(); current != arguments.end(); ++current) {
        const std::string_view kOption = *current;
        const auto kNextValue = [&current, &arguments]() -> std::optional<std::string_view> {
            const auto kFollowing = std::next(current);
            if (kFollowing == arguments.end()) {
                return std::nullopt;
            }
            current = kFollowing;
            return *current;
        };
        if (kOption == "--format") {
            const auto kValue = kNextValue();
            if (!kValue || (*kValue != "human" && *kValue != "json")) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--format", "expected human or json"});
            }
            options.format = *kValue == "json" ? OutputFormat::Json : OutputFormat::Human;
        } else if (kOption == "--host") {
            const auto kValue = kNextValue();
            if (!kValue) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--host", "missing host ID"});
            }
            options.hostId = std::string(*kValue);
        } else if (kOption == "--root") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--root", "missing repository path"});
            }
            options.repositoryRoot = std::filesystem::path(*kValue);
            hasRoot = true;
        } else if (kOption == "--tool") {
            const auto kValue = kNextValue();
            if (!kValue) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--tool", "missing tool ID"});
            }
            options.toolId = std::string(*kValue);
        } else if (kOption == "--report") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(
                    Failure{FailureCode::InvalidArguments, "--report", "missing repository-relative report path"});
            }
            options.reportPath = std::string(*kValue);
        } else if (kOption == "--record") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--record", "missing record path"});
            }
            options.recordPath = std::string(*kValue);
        } else if (kOption == "--descriptor") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(
                    Failure{FailureCode::InvalidArguments, "--descriptor", "missing descriptor path"});
            }
            options.descriptorPath = std::string(*kValue);
        } else if (kOption == "--source") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(
                    Failure{FailureCode::InvalidArguments, "--source", "missing repository-relative content path"});
            }
            options.sourcePath = std::string(*kValue);
        } else if (kOption == "--digest") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--digest", "missing content digest"});
            }
            options.digest = std::string(*kValue);
        } else if (kOption == "--media") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--media", "missing media type"});
            }
            options.mediaType = std::string(*kValue);
        } else {
            return std::unexpected(Failure{FailureCode::InvalidArguments, std::string(kOption), "unknown option"});
        }
    }
    if (!hasRoot) {
        return std::unexpected(Failure{FailureCode::InvalidArguments, "--root", "repository root is required"});
    }
    // Child-process launches and capture paths require an absolute root:
    // CreateProcessW does not reliably resolve relative application and
    // working-directory paths.
    std::error_code rootError;
    auto absoluteRoot = std::filesystem::weakly_canonical(options.repositoryRoot, rootError);
    if (rootError) {
        return std::unexpected(Failure{
            FailureCode::InvalidPath, options.repositoryRoot.generic_string(), "failed to resolve repository root"});
    }
    options.repositoryRoot = std::move(absoluteRoot);
    return options;
}

int fail(std::ostream& errors, const Failure& failure, OutputFormat format) {
    renderFailure(errors, failure, format);
    return failure.code == FailureCode::InvalidArguments ? 2 : 3;
}

int emitRequestedReport(const ParsedOptions& options, std::string_view content, std::ostream& errors) {
    if (!options.reportPath) {
        return 0;
    }
    auto reportPath = resolveReportPath(options.repositoryRoot, *options.reportPath);
    if (!reportPath) {
        return fail(errors, reportPath.error(), options.format);
    }
    if (auto status = writeReportAtomically(*reportPath, content); !status) {
        return fail(errors, status.error(), options.format);
    }
    return 0;
}

int validateOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto snapshot = validateRepository(options.repositoryRoot);
    if (!snapshot) {
        return fail(errors, snapshot.error(), options.format);
    }
    if (const auto kReportResult = emitRequestedReport(options, buildAuthorityValidationReport(*snapshot), errors);
        kReportResult != 0) {
        return kReportResult;
    }
    renderSuccess(output,
                  "validate_repository",
                  std::to_string(snapshot->tools.size()) + " repository tool(s) valid",
                  options.format);
    return 0;
}

int graphOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto snapshot = validateRepository(options.repositoryRoot);
    if (!snapshot) {
        return fail(errors, snapshot.error(), options.format);
    }
    if (const auto kReportResult = emitRequestedReport(options, buildRepositoryGraphReport(*snapshot), errors);
        kReportResult != 0) {
        return kReportResult;
    }

    if (options.format == OutputFormat::Human) {
        for (const auto& tool : snapshot->tools) {
            output << tool.id << " -> " << tool.cmakeTarget << '\n';
        }
    } else {
        output << "{\"ok\":true,\"operation\":\"graph_repository\",\"tools\":[";
        bool first = true;
        for (const auto& tool : snapshot->tools) {
            if (!first) {
                output << ',';
            }
            first = false;
            output << "{\"id\":";
            writeJsonString(output, tool.id);
            output << ",\"target\":";
            writeJsonString(output, tool.cmakeTarget);
            output << '}';
        }
        output << "]}\n";
    }
    return 0;
}

int explainOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    if (!options.toolId) {
        return fail(errors, Failure{FailureCode::InvalidArguments, "--tool", "tool ID is required"}, options.format);
    }
    auto snapshot = validateRepository(options.repositoryRoot);
    if (!snapshot) {
        return fail(errors, snapshot.error(), options.format);
    }
    const auto kTool = std::ranges::find(snapshot->tools, *options.toolId, &ToolInfo::id);
    if (kTool == snapshot->tools.end()) {
        return fail(errors,
                    Failure{FailureCode::MissingInput, *options.toolId, "tool is not a repository member"},
                    options.format);
    }
    if (const auto kReportResult = emitRequestedReport(options, buildDependencyClosureReport(*kTool), errors);
        kReportResult != 0) {
        return kReportResult;
    }

    output << kTool->id << "\n  third_party:";
    for (const auto& dependency : kTool->thirdPartyDependencies) {
        output << ' ' << dependency;
    }
    output << "\n  managed_tools:";
    for (const auto& dependency : kTool->managedToolDependencies) {
        output << ' ' << dependency;
    }
    output << '\n';
    return 0;
}

int sourceOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto report = inspectSourceOwnership(options.repositoryRoot);
    if (!report) {
        return fail(errors, report.error(), options.format);
    }
    const std::string kReportContent = buildSourceOwnershipReport(*report);
    if (const auto kReportResult = emitRequestedReport(options, kReportContent, errors); kReportResult != 0) {
        return kReportResult;
    }
    // A caller that asked for JSON gets the same document `--report` writes.
    // Every other operation answers `--format json` with a machine-readable
    // result, and a tab-separated listing in its place would be the one command
    // whose output shape depends on knowing that it is the exception.
    if (options.format == OutputFormat::Json) {
        output << kReportContent;
    } else {
        for (const auto& entry : *report) {
            output << entry.lines << '\t' << entry.owner << '\t' << entry.path << '\n';
        }
    }
    // STD-0001 requires warning output at 600 physical lines and blocking output
    // at 1,000. These go to the diagnostic stream so the ordinary machine-readable
    // listing above stays parseable.
    for (const auto& entry : *report) {
        if (entry.gate == SourceGate::Ok) {
            continue;
        }
        errors << sourceGateSeverity(entry.gate) << ": " << entry.path << " reaches " << entry.lines
               << " physical lines and requires "
               << (entry.gate == SourceGate::FeatureGrowthStopped
                       ? "a decomposition or documented containment plan before unrelated feature growth"
                       : "an explicit STD-0001 ownership review before further feature growth")
               << '\n';
    }
    return 0;
}

int offlineOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    if (!options.hostId) {
        return fail(errors, Failure{FailureCode::InvalidArguments, "--host", "host ID is required"}, options.format);
    }
    auto report = verifyOfflineInputs(options.repositoryRoot, *options.hostId);
    if (!report) {
        return fail(errors, report.error(), options.format);
    }
    if (const auto kReportResult =
            emitRequestedReport(options, buildOfflineVerificationReport(*options.hostId, *report), errors);
        kReportResult != 0) {
        return kReportResult;
    }
    renderSuccess(output,
                  "verify_offline",
                  std::to_string(report->checkedArtifacts) + " artifact(s), " + std::to_string(report->checkedBytes) +
                      " bytes",
                  options.format);
    return 0;
}

int licenseOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto review = reviewLicenses(options.repositoryRoot);
    if (!review) {
        return fail(errors, review.error(), options.format);
    }
    if (const auto kReportResult = emitRequestedReport(options, buildLicenseReviewReport(*review), errors);
        kReportResult != 0) {
        return kReportResult;
    }
    renderSuccess(output,
                  "review_licenses",
                  std::to_string(review->entries.size()) + " license entr(ies) cover " +
                      std::to_string(review->catalogEntryCount) + " catalog entr(ies), " +
                      std::to_string(review->restrictedCount) + " restricted",
                  options.format);
    return 0;
}

int pathAuditOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto audit = auditRepositoryPaths(options.repositoryRoot);
    if (!audit) {
        return fail(errors, audit.error(), options.format);
    }
    if (const auto kReportResult = emitRequestedReport(options, buildPathAuditReport(*audit), errors);
        kReportResult != 0) {
        return kReportResult;
    }
    if (!audit->envelopeViolations.empty()) {
        return fail(errors,
                    Failure{FailureCode::VerificationFailed,
                            audit->envelopeViolations.front().path,
                            "delivered material escapes the TASK-0001 write envelope"},
                    options.format);
    }
    renderSuccess(output,
                  "audit_paths",
                  std::to_string(audit->envelopeFileCount) + " envelope file(s), " +
                      std::to_string(audit->preexistingFileCount) + " pre-existing file(s), " +
                      std::to_string(audit->stagingRootEntries.size()) + " staging-excluded entr(ies), " +
                      std::to_string(audit->unclassifiedRootEntries.size()) + " unclassified workspace entr(ies)",
                  options.format);
    return 0;
}

int shippingClosureOperation(const ParsedOptions& options, std::ostream& output, std::ostream& errors) {
    auto snapshot = validateRepository(options.repositoryRoot);
    if (!snapshot) {
        return fail(errors, snapshot.error(), options.format);
    }
    auto audit = auditShippingClosure(snapshot->root, *snapshot);
    if (!audit) {
        return fail(errors, audit.error(), options.format);
    }
    if (const auto kReportResult = emitRequestedReport(options, buildShippingClosureReport(*audit), errors);
        kReportResult != 0) {
        return kReportResult;
    }
    if (!audit->allPassed()) {
        const auto kFailed = std::ranges::find(audit->checks, false, &ShippingClosureCheck::pass);
        return fail(errors,
                    Failure{FailureCode::VerificationFailed,
                            kFailed->check + ": " + kFailed->subject,
                            "shipping-closure audit check failed"},
                    options.format);
    }
    renderSuccess(
        output, "audit_shipping_closure", std::to_string(audit->checks.size()) + " check(s) passed", options.format);
    return 0;
}

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
    auto descriptor = describeBytes(kCanonical, kRawRunReceiptMediaType);
    if (!descriptor) {
        return failRecord(output, errors, descriptor.error(), options.format);
    }
    auto summary = validateRawRunReceipt(options.repositoryRoot, *recordPath, *parsed, descriptor->mediaType);
    if (!summary) {
        return failRecord(output, errors, summary.error(), options.format);
    }
    if (options.format == OutputFormat::Json) {
        output << buildCanonicalizeOutput(*descriptor, *summary);
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

    Descriptor descriptor{std::string(kRawRunReceiptMediaType), bytes->size(), {}};
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
        if (auto status = verifyDescriptor(*supplied, *bytes, kRawRunReceiptMediaType); !status) {
            return failRecord(output, errors, status.error(), options.format);
        }
        descriptor = *supplied;
    } else {
        auto computed = describeBytes(*bytes, kRawRunReceiptMediaType);
        if (!computed) {
            return failRecord(output, errors, computed.error(), options.format);
        }
        descriptor = *computed;
    }

    auto summary = validateRawRunReceipt(options.repositoryRoot, *recordPath, *record, descriptor.mediaType);
    if (!summary) {
        return failRecord(output, errors, summary.error(), options.format);
    }
    if (options.format == OutputFormat::Json) {
        output << buildValidateOutput(descriptor, *summary);
        return 0;
    }
    renderSuccess(output, "validate_record", summary->runId + " is canonical and valid", options.format);
    return 0;
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

int emitDescriptor(std::ostream& output, const Descriptor& descriptor) {
    output << serializeCanonical(describeAsValue(descriptor));
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

} // namespace

int runCommand(std::span<const std::string_view> arguments, std::ostream& output, std::ostream& errors) {
    if (arguments.empty()) {
        return fail(
            errors, Failure{FailureCode::InvalidArguments, "command", "expected an operation"}, OutputFormat::Human);
    }

    const std::string_view kOperation = arguments.front();
    const bool kIsOffline = kOperation == "verify-offline";
    std::string_view subject;
    std::size_t optionStart = 1;
    if (!kIsOffline) {
        if (arguments.size() < 2) {
            return fail(errors,
                        Failure{FailureCode::InvalidArguments, "command", "expected an operation subject"},
                        OutputFormat::Human);
        }
        subject = *std::next(arguments.begin());
        optionStart = 2;
    }
    auto options = parseOptions(arguments.subspan(optionStart));
    if (!options) {
        return fail(errors, options.error(), OutputFormat::Human);
    }

    // Neither record operation accepts a report destination. `validate` must
    // not be able to write a corrected form anywhere, and the strongest way to
    // say that is to leave it with nowhere to write.
    const bool kIsRecordOperation = subject == "record" && (kOperation == "canonicalize" || kOperation == "validate");
    if (kIsRecordOperation && options->reportPath) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments, "--report", "record operations write no report"},
                    options->format);
    }

    // A store operation writes exactly one place, the blob path its digest
    // derives, and it has nowhere else to write for the same reason.
    const bool kIsBlobOperation =
        subject == "blob" && (kOperation == "put" || kOperation == "verify" || kOperation == "get");
    if (kIsBlobOperation && options->reportPath) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments, "--report", "store operations write no report"},
                    options->format);
    }
    if (kOperation == "put" && subject == "blob") {
        return putBlobOperation(*options, output, errors);
    }
    if (kOperation == "verify" && subject == "blob") {
        return verifyBlobOperation(*options, output, errors);
    }
    if (kOperation == "get" && subject == "blob") {
        return getBlobOperation(*options, output, errors);
    }
    if (kOperation == "canonicalize" && subject == "record") {
        return canonicalizeOperation(*options, output, errors);
    }
    if (kOperation == "validate" && subject == "record") {
        return validateRecordOperation(*options, output, errors);
    }
    if (kOperation == "validate" && subject == "repository") {
        return validateOperation(*options, output, errors);
    }
    if (kOperation == "graph" && subject == "repository") {
        return graphOperation(*options, output, errors);
    }
    if (kOperation == "explain" && subject == "dependency") {
        return explainOperation(*options, output, errors);
    }
    if (kOperation == "inspect" && subject == "source-ownership") {
        return sourceOperation(*options, output, errors);
    }
    if (kOperation == "review" && subject == "licenses") {
        return licenseOperation(*options, output, errors);
    }
    if (kOperation == "audit" && subject == "paths") {
        return pathAuditOperation(*options, output, errors);
    }
    if (kOperation == "audit" && subject == "shipping-closure") {
        return shippingClosureOperation(*options, output, errors);
    }
    if (kIsOffline) {
        return offlineOperation(*options, output, errors);
    }
    return fail(errors, Failure{FailureCode::InvalidArguments, "command", "unsupported operation"}, options->format);
}

} // namespace rawframe::tool::evidence
