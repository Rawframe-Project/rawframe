#pragma once

#include "failure.h"
#include "json_reader.h"
#include "repository_scan.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

// One membership array of the root index, kept with the name it has there so a
// finding can say which authority listed the entry.
struct MembershipArray {
    std::string name;
    std::vector<std::string> entries;
};

struct LoadedManifest {
    std::string path;
    // Empty when the file could not be read. A listed manifest that is absent is
    // a finding about the repository, not a failure of the tool, so loading
    // records the absence and carries on.
    bool present = false;
    std::string readFailure;
    JsonDocument document;
};

struct ToolManifest {
    std::string manifestPath;
    std::string root;
    std::string id;
    std::string cmakeTarget;
    std::vector<std::string> thirdParty;
    std::vector<std::string> managedTools;
};

struct CatalogEntry {
    std::string id;
    std::string acquisitionClass;
    std::string providerType;
    std::string providerReference;
};

struct RepositoryModel {
    std::filesystem::path root;
    RepositoryScan scan;

    LoadedManifest index;
    std::vector<MembershipArray> membership;
    std::string evidenceIndexPath;

    // Every manifest whose maintained form SPEC-0001 governs: the root index,
    // every manifest it lists, and the rule corpus. Evidence records are
    // deliberately absent, because their normal form is the canonical encoding
    // SPEC-0017 fixes and `rf-evidence` owns it.
    std::vector<LoadedManifest> manifests;
    std::vector<ToolManifest> tools;
    std::vector<CatalogEntry> catalog;

    // The build files reachable from the root build file, derived rather than
    // listed. A build lane written down by hand stops covering the file someone
    // adds next; one that is followed cannot.
    std::vector<std::string> buildLane;

    std::string corpusPath;

    [[nodiscard]] const MembershipArray* membershipArray(std::string_view name) const noexcept;
};

[[nodiscard]] Result<RepositoryModel> loadRepositoryModel(const std::filesystem::path& root,
                                                          std::string_view corpusRelativePath);

} // namespace rawframe::tool::archcheck
