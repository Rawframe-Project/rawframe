#pragma once

#include "failure.h"
#include "repository_validator.h"

#include <filesystem>

namespace rawframe::tool::evidence {

[[nodiscard]] Status validateDependencyAuthorities(const std::filesystem::path& repositoryRoot,
                                                   const RepositorySnapshot& repository);

} // namespace rawframe::tool::evidence
