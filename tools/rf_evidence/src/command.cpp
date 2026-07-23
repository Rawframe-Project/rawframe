#include "command.h"

#include "diagnostic.h"
#include "license_review.h"
#include "offline_verifier.h"
#include "path_audit.h"
#include "report_writer.h"
#include "repository_validator.h"
#include "shipping_closure.h"
#include "source_inspector.h"

#include <algorithm>
#include <filesystem>
#include <iterator>
#include <optional>
#include <ostream>
#include <string>
#include <system_error>

namespace rawframe::tool::evidence {

namespace {

struct ParsedOptions {
    std::filesystem::path repositoryRoot;
    std::optional<std::string> toolId;
    std::optional<std::string> hostId;
    std::optional<std::string> reportPath;
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
    if (const auto kReportResult = emitRequestedReport(options, buildSourceOwnershipReport(*report), errors);
        kReportResult != 0) {
        return kReportResult;
    }
    for (const auto& entry : *report) {
        output << entry.lines << '\t' << entry.owner << '\t' << entry.path << '\n';
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
