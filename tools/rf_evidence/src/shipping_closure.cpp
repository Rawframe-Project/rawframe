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

constexpr std::string_view kRepositoryToolRoot = "tools/";

/// Whether the repository index keeps production membership and repository-tool
/// membership on opposite sides of the ADR-0022 boundary: no production entry
/// resolves beneath the repository-tool root, and every tool entry does.
///
/// This check asserted that production membership was empty until TASK-0011.
/// That was a true observation about the repository on the day it was written
/// and not the invariant: `rawframe.base` is a production module the accepted
/// Plan orders, and an audit that fails the moment the project does what it
/// planned is measuring the calendar. Emptiness also proved nothing about the
/// boundary, since it would have held equally in a repository with no tools.
/// What must stay true for as long as `tools/` exists is that a repository tool
/// never appears where a shipping closure resolves its members, which is what
/// this reads instead.
Result<bool> membershipRootsSeparated(const std::filesystem::path& repositoryRoot) {
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

    // A missing array stays a typed failure rather than a quiet false. An
    // authority that lost one of its membership kinds is malformed, and reading
    // that as a failed check would report a boundary violation where the real
    // defect is that nothing declared the membership at all.
    const auto kReadArray = [&](std::string_view field) -> Result<simdjson::dom::array> {
        simdjson::dom::array members;
        if (const auto kError = root.at_key(field).get_array().get(members); kError) {
            return std::unexpected(Failure{FailureCode::InvalidManifest,
                                           repositoryPath->generic_string(),
                                           std::string(field) + " membership array is missing"});
        }
        return members;
    };

    bool separated = true;
    for (const std::string_view kField : {"modules", "targets", "packagingPolicies", "profiles"}) {
        auto members = kReadArray(kField);
        if (!members) {
            return std::unexpected(members.error());
        }
        for (const auto kMember : *members) {
            std::string_view path;
            if (const auto kError = kMember.get_string().get(path); kError) {
                return std::unexpected(Failure{FailureCode::InvalidManifest,
                                               repositoryPath->generic_string(),
                                               std::string(kField) + " membership entries must be strings"});
            }
            if (path.starts_with(kRepositoryToolRoot)) {
                separated = false;
            }
        }
    }

    auto tools = kReadArray("tools");
    if (!tools) {
        return std::unexpected(tools.error());
    }
    for (const auto kTool : *tools) {
        std::string_view path;
        if (const auto kError = kTool.get_string().get(path); kError) {
            return std::unexpected(Failure{FailureCode::InvalidManifest,
                                           repositoryPath->generic_string(),
                                           "tools membership entries must be strings"});
        }
        if (!path.starts_with(kRepositoryToolRoot)) {
            separated = false;
        }
    }
    return separated;
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

/// Whether every production module manifest in the tree lies beneath `source/`.
///
/// This scanned for the absence of any `module.json` at all until TASK-0011, for
/// the same reason and with the same defect as the membership check above. A
/// manifest is not a leak; a manifest inside the repository-tool root is, and so
/// is one in a root that declares nothing. The scan is still whole-repository
/// rather than membership-driven, because an undeclared manifest in the wrong
/// place is exactly what a membership-driven reader would not see.
Result<bool> moduleManifestsOnlyBeneathSource(const std::filesystem::path& repositoryRoot) {
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
            const auto kRelative = std::filesystem::relative(iterator->path(), repositoryRoot, error);
            if (error || !kRelative.generic_string().starts_with("source/")) {
                return false;
            }
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

    auto rootsSeparated = membershipRootsSeparated(repositoryRoot);
    if (!rootsSeparated) {
        return std::unexpected(rootsSeparated.error());
    }
    audit.checks.push_back(ShippingClosureCheck{"membership_roots_separated", "repository.json", *rootsSeparated});

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

    // Product roots that must not exist yet. `evidence` was one of them until
    // ADR-0022 admitted maintained evidence as repository material and TASK-0005
    // created it; its absence was never the invariant, and asserting it now
    // would make a legitimate root look like a shipping leak. What must stay
    // true of it is that nothing there is a production module, which
    // moduleManifestsOnlyBeneathSource below proves over the whole repository,
    // and that nothing there is generated, which the path audit proves.
    //
    // `source` left this list with TASK-0011 for exactly the same reason.
    // SPEC-0007 gives every production module a root beneath it, so the first
    // module the accepted Plan orders creates it, and its absence was a fact
    // about the calendar rather than about the tool boundary.
    constexpr std::array kForbiddenRoots{
        std::string_view{"apps"},
        std::string_view{"games"},
        std::string_view{"packages"},
        std::string_view{"sdk"},
    };
    for (const auto kRoot : kForbiddenRoots) {
        std::error_code error;
        const bool kAbsent = !std::filesystem::exists(repositoryRoot / kRoot, error) && !error;
        audit.checks.push_back(ShippingClosureCheck{"shipping_root_absent", std::string(kRoot), kAbsent});
    }

    auto modulesPlacedCorrectly = moduleManifestsOnlyBeneathSource(snapshot.root);
    if (!modulesPlacedCorrectly) {
        return std::unexpected(modulesPlacedCorrectly.error());
    }
    audit.checks.push_back(
        ShippingClosureCheck{"module_manifest_only_beneath_source", "module.json", *modulesPlacedCorrectly});

    std::ranges::sort(audit.checks, [](const ShippingClosureCheck& left, const ShippingClosureCheck& right) {
        return std::tie(left.check, left.subject) < std::tie(right.check, right.subject);
    });
    return audit;
}

} // namespace rawframe::tool::evidence
