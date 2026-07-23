#pragma once

#include "failure.h"

#include <filesystem>

namespace rawframe::tool::evidence {

[[nodiscard]] Status verifySchemaOracleVersion(const std::filesystem::path& repositoryRoot);
[[nodiscard]] Status validateJsonShape(const std::filesystem::path& repositoryRoot,
                                       const std::filesystem::path& schemaPath,
                                       const std::filesystem::path& instancePath);

} // namespace rawframe::tool::evidence
