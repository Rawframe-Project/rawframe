#pragma once

#include "failure.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::evidence {

struct SourceOwnershipEntry {
    std::string path;
    std::size_t lines;
    std::string owner;
};

[[nodiscard]] Result<std::vector<SourceOwnershipEntry>>
inspectSourceOwnership(const std::filesystem::path& repositoryRoot);

} // namespace rawframe::tool::evidence
