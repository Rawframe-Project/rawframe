#pragma once

#include "failure.h"

#include <filesystem>
#include <string_view>

namespace rawframe::tool::evidence {

[[nodiscard]] Result<std::filesystem::path> resolveRepositoryPath(const std::filesystem::path& repositoryRoot,
                                                                  std::string_view relativePath);

[[nodiscard]] std::string portableLowercasePath(const std::filesystem::path& path);

} // namespace rawframe::tool::evidence
