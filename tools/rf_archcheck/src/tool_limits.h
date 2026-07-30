#pragma once

#include <cstddef>

namespace rawframe::tool::archcheck {

// The tool reads contributor-authored manifests and sources, so every parser is
// bounded before it allocates. SPEC-0044 requires that exhaustion is exit 3 with
// a typed reason and never a truncated clean result: a ceiling that silently
// stopped reading would report the part of the repository it managed to see as
// the whole of it.
inline constexpr std::size_t kMaximumFileBytes = std::size_t{4} * 1024 * 1024;
inline constexpr std::size_t kMaximumJsonDepth = 32;
inline constexpr std::size_t kMaximumJsonMembers = 4096;
inline constexpr std::size_t kMaximumJsonElements = 8192;
inline constexpr std::size_t kMaximumStringLength = 8192;
inline constexpr std::size_t kMaximumPathLength = 1024;
inline constexpr std::size_t kMaximumScannedFiles = 65'536;
inline constexpr std::size_t kMaximumDirectoryDepth = 24;
inline constexpr std::size_t kMaximumIncludeNodes = 16'384;
inline constexpr std::size_t kMaximumIncludeEdges = 131'072;
inline constexpr std::size_t kMaximumFindings = 65'536;
inline constexpr std::size_t kMaximumRules = 4096;

} // namespace rawframe::tool::archcheck
