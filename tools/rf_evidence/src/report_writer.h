#pragma once

#include "failure.h"
#include "license_review.h"
#include "offline_verifier.h"
#include "path_audit.h"
#include "repository_validator.h"
#include "shipping_closure.h"
#include "source_inspector.h"

#include <filesystem>
#include <span>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

// The only root the tool manifest authorizes for retained diagnostic reports.
inline constexpr std::string_view kReportRootPrefix = "out/reports/task-0001/";

[[nodiscard]] Result<std::filesystem::path> resolveReportPath(const std::filesystem::path& repositoryRoot,
                                                              std::string_view reportArgument);

[[nodiscard]] Status writeReportAtomically(const std::filesystem::path& reportPath, std::string_view content);

[[nodiscard]] std::string buildAuthorityValidationReport(const RepositorySnapshot& snapshot);
[[nodiscard]] std::string buildRepositoryGraphReport(const RepositorySnapshot& snapshot);
[[nodiscard]] std::string buildDependencyClosureReport(const ToolInfo& tool);
[[nodiscard]] std::string buildSourceOwnershipReport(std::span<const SourceOwnershipEntry> entries);
[[nodiscard]] std::string buildOfflineVerificationReport(std::string_view hostId,
                                                         const OfflineVerificationReport& report);
[[nodiscard]] std::string buildLicenseReviewReport(const LicenseReview& review);
[[nodiscard]] std::string buildPathAuditReport(const PathAudit& audit);
[[nodiscard]] std::string buildShippingClosureReport(const ShippingClosureAudit& audit);

} // namespace rawframe::tool::evidence
