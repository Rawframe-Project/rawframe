#include "report_writer.h"

#include "diagnostic.h"
#include "path_policy.h"

#include <fstream>
#include <sstream>
#include <system_error>

namespace rawframe::tool::evidence {

namespace {

void writeField(std::ostream& output, std::string_view key, std::string_view value) {
    writeJsonString(output, key);
    output << ':';
    writeJsonString(output, value);
}

void writeField(std::ostream& output, std::string_view key, std::uintmax_t value) {
    writeJsonString(output, key);
    output << ':' << value;
}

void writeField(std::ostream& output, std::string_view key, bool value) {
    writeJsonString(output, key);
    output << ':' << (value ? "true" : "false");
}

void writeStringArray(std::ostream& output, std::string_view key, std::span<const std::string> values) {
    writeJsonString(output, key);
    output << ":[";
    bool first = true;
    for (const auto& value : values) {
        if (!first) {
            output << ',';
        }
        first = false;
        writeJsonString(output, value);
    }
    output << ']';
}

void beginReport(std::ostream& output, std::string_view operation) {
    output << '{';
    writeField(output, "schemaVersion", std::uintmax_t{1});
    output << ',';
    writeField(output, "operation", operation);
}

std::string endReport(std::ostringstream& output) {
    output << "}\n";
    return std::move(output).str();
}

} // namespace

Result<std::filesystem::path> resolveReportPath(const std::filesystem::path& repositoryRoot,
                                                std::string_view reportArgument) {
    if (!reportArgument.starts_with(kReportRootPrefix)) {
        return std::unexpected(Failure{FailureCode::InvalidPath,
                                       std::string(reportArgument),
                                       "reports must stay beneath " + std::string(kReportRootPrefix)});
    }
    if (!reportArgument.ends_with(".json")) {
        return std::unexpected(
            Failure{FailureCode::InvalidPath, std::string(reportArgument), "reports must be .json files"});
    }
    return resolveRepositoryPath(repositoryRoot, reportArgument);
}

Status writeReportAtomically(const std::filesystem::path& reportPath, std::string_view content) {
    std::error_code error;
    std::filesystem::create_directories(reportPath.parent_path(), error);
    if (error) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, reportPath.generic_string(), "cannot create the report directory"});
    }

    auto stagingPath = reportPath;
    stagingPath += ".tmp";
    {
        std::ofstream output(stagingPath, std::ios::binary | std::ios::trunc);
        if (!output) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, stagingPath.generic_string(), "cannot open the report staging file"});
        }
        output.write(content.data(), static_cast<std::streamsize>(content.size()));
        output.flush();
        if (!output) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, stagingPath.generic_string(), "cannot write the report staging file"});
        }
    }
    std::filesystem::rename(stagingPath, reportPath, error);
    if (error) {
        std::error_code removeError;
        std::filesystem::remove(stagingPath, removeError);
        return std::unexpected(
            Failure{FailureCode::IoFailure, reportPath.generic_string(), "cannot publish the report atomically"});
    }
    return {};
}

std::string buildAuthorityValidationReport(const RepositorySnapshot& snapshot) {
    std::ostringstream output;
    beginReport(output, "validate_repository");
    output << ',';
    writeField(output, "ok", true);
    output << ',';
    writeJsonString(output, "validatedAuthorities");
    output << ":[";
    bool first = true;
    for (const std::string_view kAuthority : {"repository.json",
                                              "third_party/catalog.json",
                                              "third_party/toolchain.lock.json",
                                              "third_party/artifacts.lock.json"}) {
        if (!first) {
            output << ',';
        }
        first = false;
        writeJsonString(output, kAuthority);
    }
    for (const auto& tool : snapshot.tools) {
        output << ',';
        writeJsonString(output, tool.manifestPath);
    }
    output << "],";
    writeField(output, "schemaOracleVerified", true);
    output << ',';
    writeField(output, "dependencyAuthoritiesValidated", true);
    output << ',';
    writeJsonString(output, "tools");
    output << ":[";
    first = true;
    for (const auto& tool : snapshot.tools) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "id", tool.id);
        output << ',';
        writeField(output, "manifestPath", tool.manifestPath);
        output << ',';
        writeField(output, "cmakeTarget", tool.cmakeTarget);
        output << '}';
    }
    output << ']';
    return endReport(output);
}

std::string buildRepositoryGraphReport(const RepositorySnapshot& snapshot) {
    std::ostringstream output;
    beginReport(output, "graph_repository");
    output << ',';
    writeField(output, "ok", true);
    output << ',';
    writeField(output, "productionModuleCount", std::uintmax_t{0});
    output << ',';
    writeJsonString(output, "tools");
    output << ":[";
    bool first = true;
    for (const auto& tool : snapshot.tools) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "id", tool.id);
        output << ',';
        writeField(output, "cmakeTarget", tool.cmakeTarget);
        output << ',';
        writeStringArray(output, "thirdParty", tool.thirdPartyDependencies);
        output << ',';
        writeStringArray(output, "managedTools", tool.managedToolDependencies);
        output << '}';
    }
    output << ']';
    return endReport(output);
}

std::string buildDependencyClosureReport(const ToolInfo& tool) {
    std::ostringstream output;
    beginReport(output, "explain_dependency");
    output << ',';
    writeField(output, "ok", true);
    output << ',';
    writeField(output, "tool", tool.id);
    output << ',';
    writeStringArray(output, "thirdParty", tool.thirdPartyDependencies);
    output << ',';
    writeStringArray(output, "managedTools", tool.managedToolDependencies);
    output << ',';
    writeField(output, "productionReverseEdges", std::uintmax_t{0});
    return endReport(output);
}

std::string buildSourceOwnershipReport(std::span<const SourceOwnershipEntry> entries) {
    std::ostringstream output;
    std::size_t reviewCount = 0;
    std::size_t growthStopCount = 0;
    // STD-0001 requires exempt and non-exempt files to be reported separately,
    // so the two counts are stated rather than left to be derived by whoever
    // reads the listing.
    std::size_t maintainedCount = 0;
    std::size_t exemptCount = 0;
    for (const auto& entry : entries) {
        if (entry.gate == SourceGate::OwnershipReviewRequired) {
            ++reviewCount;
        } else if (entry.gate == SourceGate::FeatureGrowthStopped) {
            ++growthStopCount;
        }
        if (isExemptFromLineThresholds(entry.classification)) {
            ++exemptCount;
        } else {
            ++maintainedCount;
        }
    }

    beginReport(output, "inspect_source_ownership");
    output << ',';
    writeField(output, "ok", true);
    output << ',';
    writeField(output, "fileCount", entries.size());
    output << ',';
    writeField(output, "maintainedFileCount", maintainedCount);
    output << ',';
    writeField(output, "exemptFileCount", exemptCount);
    output << ',';
    writeField(output, "ownershipReviewLines", kOwnershipReviewLines);
    output << ',';
    writeField(output, "featureGrowthStopLines", kFeatureGrowthStopLines);
    output << ',';
    writeField(output, "hardFailureLines", kHardFailureLines);
    output << ',';
    writeField(output, "ownershipReviewCount", reviewCount);
    output << ',';
    writeField(output, "featureGrowthStopCount", growthStopCount);
    output << ',';
    writeJsonString(output, "files");
    output << ":[";
    bool first = true;
    for (const auto& entry : entries) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "path", entry.path);
        output << ',';
        writeField(output, "lines", entry.lines);
        output << ',';
        writeField(output, "owner", entry.owner);
        output << ',';
        writeField(output, "classification", std::string{sourceClassificationName(entry.classification)});
        output << ',';
        writeField(output, "exempt", isExemptFromLineThresholds(entry.classification));
        output << ',';
        writeField(output, "gate", std::string{sourceGateName(entry.gate)});
        output << ',';
        writeField(output, "severity", std::string{sourceGateSeverity(entry.gate)});
        output << '}';
    }
    output << ']';
    return endReport(output);
}

std::string buildOfflineVerificationReport(std::string_view hostId, const OfflineVerificationReport& report) {
    std::ostringstream output;
    beginReport(output, "verify_offline");
    output << ',';
    writeField(output, "ok", true);
    output << ',';
    writeField(output, "host", hostId);
    output << ',';
    writeField(output, "checkedArtifacts", report.checkedArtifacts);
    output << ',';
    writeField(output, "checkedBytes", report.checkedBytes);
    output << ',';
    writeField(output, "network", true);
    return endReport(output);
}

std::string buildLicenseReviewReport(const LicenseReview& review) {
    std::ostringstream output;
    beginReport(output, "review_licenses");
    output << ',';
    writeField(output, "ok", true);
    output << ',';
    writeField(output, "catalogEntryCount", review.catalogEntryCount);
    output << ',';
    writeField(output, "restrictedCount", review.restrictedCount);
    output << ',';
    writeJsonString(output, "materials");
    output << ":[";
    bool first = true;
    for (const auto& material : review.materials) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "path", material.path);
        output << ',';
        writeField(output, "byteSize", material.byteSize);
        output << ',';
        writeField(output, "sha256", material.sha256);
        output << '}';
    }
    output << "],";
    writeJsonString(output, "entries");
    output << ":[";
    first = true;
    for (const auto& entry : review.entries) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "id", entry.licenseId);
        output << ',';
        writeStringArray(output, "catalogIds", entry.catalogIds);
        output << ',';
        writeField(output, "spdxExpression", entry.spdxExpression);
        output << ',';
        writeField(output, "materialPath", entry.materialPath);
        output << ',';
        writeField(output, "sectionHeading", entry.sectionHeading);
        output << ',';
        writeField(output, "redistribution", entry.redistribution);
        output << ',';
        writeField(output, "approval", entry.approval);
        output << ',';
        writeField(output, "advisoryPolicy", entry.advisoryPolicy);
        output << '}';
    }
    output << ']';
    return endReport(output);
}

namespace {

void writePathEntries(std::ostream& output, std::string_view key, std::span<const PathAuditEntry> entries) {
    writeJsonString(output, key);
    output << ":[";
    bool first = true;
    for (const auto& entry : entries) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "path", entry.path);
        output << ',';
        writeField(output, "classification", entry.classification);
        output << '}';
    }
    output << ']';
}

} // namespace

std::string buildPathAuditReport(const PathAudit& audit) {
    std::ostringstream output;
    beginReport(output, "audit_paths");
    output << ',';
    writeField(output, "ok", audit.envelopeViolations.empty());
    output << ',';
    writeField(output, "envelopeFileCount", audit.envelopeFileCount);
    output << ',';
    writeField(output, "preexistingFileCount", audit.preexistingFileCount);
    output << ',';
    writePathEntries(output, "envelopeViolations", audit.envelopeViolations);
    output << ',';
    writePathEntries(output, "unclassifiedRootEntries", audit.unclassifiedRootEntries);
    output << ',';
    writePathEntries(output, "stagingExcludedRootEntries", audit.stagingRootEntries);
    output << ',';
    writeStringArray(output, "envelopeFiles", audit.envelopeFiles);
    return endReport(output);
}

std::string buildShippingClosureReport(const ShippingClosureAudit& audit) {
    std::ostringstream output;
    beginReport(output, "audit_shipping_closure");
    output << ',';
    writeField(output, "ok", audit.allPassed());
    output << ',';
    writeJsonString(output, "checks");
    output << ":[";
    bool first = true;
    for (const auto& check : audit.checks) {
        if (!first) {
            output << ',';
        }
        first = false;
        output << '{';
        writeField(output, "check", check.check);
        output << ',';
        writeField(output, "subject", check.subject);
        output << ',';
        writeField(output, "pass", check.pass);
        output << '}';
    }
    output << ']';
    return endReport(output);
}

} // namespace rawframe::tool::evidence
