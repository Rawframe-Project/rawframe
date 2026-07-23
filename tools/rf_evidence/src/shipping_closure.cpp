#include "shipping_closure.h"

#include "file_reader.h"
#include "path_policy.h"

#include <algorithm>
#include <array>
#include <simdjson.h>
#include <string_view>
#include <tuple>

namespace rawframe::tool::evidence {

namespace {

constexpr std::size_t kMaximumAuditedFiles = 65'536;

Result<bool> productionMembershipEmpty(const std::filesystem::path& repositoryRoot) {
    auto repositoryPath = resolveRepositoryPath(repositoryRoot, "repository.json");
    if (!repositoryPath) {
        return std::unexpected(repositoryPath.error());
    }
    auto input = readBoundedFile(*repositoryPath);
    if (!input) {
        return std::unexpected(input.error());
    }
    simdjson::dom::parser parser;
    simdjson::dom::object root;
    if (const auto kError = parser.parse(*input).get_object().get(root); kError) {
        return std::unexpected(Failure{
            FailureCode::InvalidJson, repositoryPath->generic_string(), "repository membership must be an object"});
    }
    for (const std::string_view kField : {"modules", "targets", "packagingPolicies", "profiles"}) {
        simdjson::dom::array members;
        if (const auto kError = root.at_key(kField).get_array().get(members); kError) {
            return std::unexpected(Failure{FailureCode::InvalidManifest,
                                           repositoryPath->generic_string(),
                                           std::string(kField) + " membership array is missing"});
        }
        if (members.size() != 0) {
            return false;
        }
    }
    return true;
}

Result<bool> toolDistributionForbidden(const std::filesystem::path& repositoryRoot, const ToolInfo& tool) {
    auto manifestPath = resolveRepositoryPath(repositoryRoot, tool.manifestPath);
    if (!manifestPath) {
        return std::unexpected(manifestPath.error());
    }
    auto input = readBoundedFile(*manifestPath);
    if (!input) {
        return std::unexpected(input.error());
    }
    simdjson::dom::parser parser;
    simdjson::dom::object root;
    if (const auto kError = parser.parse(*input).get_object().get(root); kError) {
        return std::unexpected(
            Failure{FailureCode::InvalidJson, manifestPath->generic_string(), "tool manifest must be an object"});
    }
    simdjson::dom::object distribution;
    if (const auto kError = root.at_key("distribution").get_object().get(distribution); kError) {
        return false;
    }
    bool repositoryOnly = false;
    if (const auto kError = distribution.at_key("repositoryOnly").get_bool().get(repositoryOnly);
        (kError != 0) || !repositoryOnly) {
        return false;
    }
    for (const std::string_view kField : {"shippingClosure", "sdkExposure", "targetRoot"}) {
        std::string_view value;
        if (const auto kError = distribution.at_key(kField).get_string().get(value);
            (kError != 0) || value != "forbidden") {
            return false;
        }
    }
    return true;
}

Result<bool> noProductionModuleManifests(const std::filesystem::path& repositoryRoot) {
    std::size_t auditedEntries = 0;
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(repositoryRoot, error), end; iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, repositoryRoot.generic_string(), "failed to audit module manifests"});
        }
        ++auditedEntries;
        if (auditedEntries > kMaximumAuditedFiles) {
            return std::unexpected(Failure{
                FailureCode::LimitExceeded, repositoryRoot.generic_string(), "module audit exceeds the file limit"});
        }
        const auto kFilename = iterator->path().filename().string();
        if (iterator.depth() == 0 && (kFilename == "out" || kFilename == ".git")) {
            iterator.disable_recursion_pending();
            continue;
        }
        if (iterator->is_symlink(error)) {
            iterator.disable_recursion_pending();
            continue;
        }
        if (iterator->is_regular_file(error) && kFilename == "module.json") {
            return false;
        }
    }
    return true;
}

bool lineDefinesInstallOrExport(std::string_view line) {
    const auto kFirst = line.find_first_not_of(" \t");
    if (kFirst == std::string_view::npos) {
        return false;
    }
    const auto kTrimmed = line.substr(kFirst);
    constexpr std::array<std::string_view, 2> kCommands{"install", "export"};
    return std::ranges::any_of(kCommands, [kTrimmed](std::string_view command) {
        if (!kTrimmed.starts_with(command)) {
            return false;
        }
        const auto kRemainder = kTrimmed.substr(command.size());
        const auto kNext = kRemainder.find_first_not_of(" \t");
        return kNext != std::string_view::npos && kRemainder.substr(kNext).starts_with('(');
    });
}

Result<bool> noInstallOrExportSurface(const std::filesystem::path& repositoryRoot, const ToolInfo& tool) {
    const auto kToolRoot = std::filesystem::path(tool.manifestPath).parent_path().generic_string();
    for (const std::string_view kBuildFile : {"CMakeLists.txt", "tests/CMakeLists.txt"}) {
        auto buildPath = resolveRepositoryPath(repositoryRoot, kToolRoot + "/" + std::string(kBuildFile));
        if (!buildPath) {
            return std::unexpected(buildPath.error());
        }
        auto input = readBoundedFile(*buildPath);
        if (!input) {
            return std::unexpected(input.error());
        }
        const std::string_view kContent{input->data(), input->size()};
        std::size_t start = 0;
        while (start <= kContent.size()) {
            const auto kEnd = kContent.find('\n', start);
            const auto kLine =
                kContent.substr(start, kEnd == std::string_view::npos ? kContent.size() - start : kEnd - start);
            if (lineDefinesInstallOrExport(kLine)) {
                return false;
            }
            if (kEnd == std::string_view::npos) {
                break;
            }
            start = kEnd + 1;
        }
    }
    return true;
}

} // namespace

Result<ShippingClosureAudit> auditShippingClosure(const std::filesystem::path& repositoryRoot,
                                                  const RepositorySnapshot& snapshot) {
    ShippingClosureAudit audit;

    auto membershipEmpty = productionMembershipEmpty(repositoryRoot);
    if (!membershipEmpty) {
        return std::unexpected(membershipEmpty.error());
    }
    audit.checks.push_back(ShippingClosureCheck{"production_membership_empty", "repository.json", *membershipEmpty});

    for (const auto& tool : snapshot.tools) {
        auto distributionForbidden = toolDistributionForbidden(repositoryRoot, tool);
        if (!distributionForbidden) {
            return std::unexpected(distributionForbidden.error());
        }
        audit.checks.push_back(ShippingClosureCheck{"tool_distribution_forbidden", tool.id, *distributionForbidden});

        auto noExportSurface = noInstallOrExportSurface(repositoryRoot, tool);
        if (!noExportSurface) {
            return std::unexpected(noExportSurface.error());
        }
        audit.checks.push_back(ShippingClosureCheck{"no_install_or_export_surface", tool.id, *noExportSurface});
    }

    constexpr std::array kForbiddenRoots{
        std::string_view{"apps"},
        std::string_view{"evidence"},
        std::string_view{"games"},
        std::string_view{"packages"},
        std::string_view{"sdk"},
        std::string_view{"source"},
    };
    for (const auto kRoot : kForbiddenRoots) {
        std::error_code error;
        const bool kAbsent = !std::filesystem::exists(repositoryRoot / kRoot, error) && !error;
        audit.checks.push_back(ShippingClosureCheck{"shipping_root_absent", std::string(kRoot), kAbsent});
    }

    auto noModules = noProductionModuleManifests(snapshot.root);
    if (!noModules) {
        return std::unexpected(noModules.error());
    }
    audit.checks.push_back(ShippingClosureCheck{"no_production_module_manifest", "module.json", *noModules});

    std::ranges::sort(audit.checks, [](const ShippingClosureCheck& left, const ShippingClosureCheck& right) {
        return std::tie(left.check, left.subject) < std::tie(right.check, right.subject);
    });
    return audit;
}

} // namespace rawframe::tool::evidence
