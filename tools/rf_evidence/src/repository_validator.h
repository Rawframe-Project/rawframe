#pragma once

#include "failure.h"

#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

struct ToolInfo {
    std::string id;
    std::string manifestPath;
    std::string owner;
    std::string cmakeTarget;
    std::vector<std::string> thirdPartyDependencies;
    std::vector<std::string> managedToolDependencies;
};

struct RepositorySnapshot {
    std::filesystem::path root;
    std::vector<ToolInfo> tools;
};

[[nodiscard]] Result<RepositorySnapshot> validateRepository(const std::filesystem::path& repositoryRoot);

} // namespace rawframe::tool::evidence
