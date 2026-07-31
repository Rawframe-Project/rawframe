#pragma once

#include "failure.h"

#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::verify {

// The one report root this tool may write, matching the `filesystemWriteRoots`
// its manifest declares. A destination anywhere else is refused rather than
// created, so the manifest is a statement about behavior and not a wish.
inline constexpr std::string_view kReportRoot = "out/reports/verify";

// Resolves the repository root and proves it is one by requiring the root index
// to be there. A tool that measured whatever directory it was pointed at could
// report a clean result for a tree that is not this repository.
[[nodiscard]] Result<std::filesystem::path> resolveRepositoryRoot(const std::filesystem::path& given);

// Backslashes are a fact about one host, not about a repository path. Every
// comparison here happens after this, so a Windows coverage export and a Linux
// one describe the same unit by the same name.
[[nodiscard]] std::string normalizeSeparators(std::string_view path);

// Expresses a path from a generated artifact as a repository-relative path, or
// reports that it lies outside the repository. Coverage exports name absolute
// paths, and a standard-library header is outside by construction.
[[nodiscard]] Result<std::string> repositoryRelative(const std::filesystem::path& repositoryRoot,
                                                     std::string_view reportedPath);

// The maintained first-party source units, defined exactly as the architecture
// tool defines them: a C++ translation unit or header beneath a production or
// repository-tool root, under `src/` or `include/`, outside `tests/`. Coverage
// over anything else is a dependency's coverage and is not this repository's to
// gate.
[[nodiscard]] bool isMaintainedSourceUnit(std::string_view relativePath);

// Refuses a report destination outside the declared write root, before opening
// anything.
[[nodiscard]] Status ensureWithinReportRoot(const std::filesystem::path& repositoryRoot,
                                            const std::filesystem::path& destination);

} // namespace rawframe::tool::verify
