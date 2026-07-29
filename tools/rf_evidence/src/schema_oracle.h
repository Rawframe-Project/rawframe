#pragma once

#include "failure.h"

#include <filesystem>
#include <span>
#include <vector>

namespace rawframe::tool::evidence {

[[nodiscard]] Status verifySchemaOracleVersion(const std::filesystem::path& repositoryRoot);

// `imports` are schemas the oracle must resolve references against. A schema
// referencing another resolves it against its own absolute identifier, not
// against its directory, so a sibling file on disk is not found and must be
// handed over explicitly. Network resolution stays denied either way.
[[nodiscard]] Status validateJsonShape(const std::filesystem::path& repositoryRoot,
                                       const std::filesystem::path& schemaPath,
                                       const std::filesystem::path& instancePath,
                                       std::span<const std::filesystem::path> imports = {});

} // namespace rawframe::tool::evidence
