#include "command.h"

#include "diagnostic.h"
#include "license_review.h"
#include "offline_verifier.h"
#include "path_audit.h"
#include "record_command.h"
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
        } else if (kOption == "--plan") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--plan", "missing attempt plan path"});
            }
            options.planPath = std::string(*kValue);
        } else if (kOption == "--set-id") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(
                    Failure{FailureCode::InvalidArguments, "--set-id", "missing evidence set identity"});
            }
            options.setId = std::string(*kValue);
        } else if (kOption == "--set") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(Failure{FailureCode::InvalidArguments, "--set", "missing evidence set path"});
            }
            options.setPath = std::string(*kValue);
        } else if (kOption == "--evaluation-id") {
            const auto kValue = kNextValue();
            if (!kValue || kValue->empty()) {
                return std::unexpected(
                    Failure{FailureCode::InvalidArguments, "--evaluation-id", "missing evaluation identity"});
            }
            options.evaluationId = std::string(*kValue);
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

    // Assembly is a ledger authority and emits one record. A report destination
    // would be a second place its output could land, and a ledger with two
    // outputs is a ledger that can disagree with itself.
    const bool kIsAssembleOperation = kOperation == "assemble" && subject == "evidence-set";
    if (kIsAssembleOperation && options->reportPath) {
        return fail(
            errors, Failure{FailureCode::InvalidArguments, "--report", "assembly writes no report"}, options->format);
    }
    if (kIsAssembleOperation) {
        return assembleOperation(*options, output, errors);
    }

    // Loading maintained authorities reads and refuses; it produces no artifact
    // at all, so it has nowhere to write for the same reason the others do not.
    if (kOperation == "load" && subject == "evidence-index" && options->reportPath) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments, "--report", "loading maintained evidence writes no report"},
                    options->format);
    }
    // Evaluation is the verdict authority and emits one record. Like assembly,
    // a report destination would give its output a second place to land, and a
    // verdict with two outputs is a verdict that can disagree with itself.
    const bool kIsEvaluateOperation = kOperation == "evaluate" && subject == "evidence-set";
    if (kIsEvaluateOperation && options->reportPath) {
        return fail(
            errors, Failure{FailureCode::InvalidArguments, "--report", "evaluation writes no report"}, options->format);
    }
    if (kIsEvaluateOperation) {
        return evaluateOperation(*options, output, errors);
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
    if (kOperation == "load" && subject == "evidence-index") {
        return loadEvidenceIndexOperation(*options, output, errors);
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
