#pragma once

#include "failure.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

struct ScannedFile {
    // Repository-relative, forward slashes, exactly the case on disk.
    std::string path;
    std::size_t bytes = 0;
};

struct RepositoryScan {
    std::filesystem::path root;
    std::vector<ScannedFile> files;
    std::vector<std::string> directories;

    [[nodiscard]] bool hasFile(std::string_view path) const noexcept;
    [[nodiscard]] bool hasDirectory(std::string_view path) const noexcept;
};

// Walks the repository once, in a fixed collation independent of the order the
// filesystem hands entries back. Two trees whose directories were created in
// different orders produce the same scan, which is what makes the findings
// document byte-identical rather than merely equivalent.
//
// `.git` and `out` are not walked: one is version-control state and the other is
// the declared generated root, and neither is maintained material any rule
// judges. A path that is a link, escapes the root, or breaks a ceiling is a
// typed failure, because a tool that quietly skipped part of the tree would
// report what it managed to read as the whole of it.
[[nodiscard]] Result<RepositoryScan> scanRepository(const std::filesystem::path& root);

// Reads a maintained text file under the byte ceiling, with CRLF collapsed to
// LF for the same reason `readJsonDocument` does it.
[[nodiscard]] Result<std::string> readTextFile(const std::filesystem::path& path);

[[nodiscard]] bool isBuildFile(std::string_view relativePath) noexcept;
[[nodiscard]] bool isFirstPartySource(std::string_view relativePath) noexcept;
[[nodiscard]] std::string_view fileExtension(std::string_view relativePath) noexcept;

} // namespace rawframe::tool::archcheck
