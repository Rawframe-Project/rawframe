#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace rawframe::tool::verify {

// The changed-line set of one change, keyed by repository-relative path.
//
// Only added and modified lines appear, because they are the only lines that
// exist in the tree the coverage export describes. A deleted line has no
// position in the new file and cannot be covered by anything, so counting it
// would make deleting code raise a coverage figure, which STD-0007 forbids by
// name.
struct ChangedLines {
    std::map<std::string, std::set<std::uint32_t>> files;

    [[nodiscard]] bool empty() const noexcept {
        return files.empty();
    }
};

// Reads a unified diff. The tool never produces one: producing it means running
// a version-control system, and a repository tool that executes processes is the
// thing SPEC-0017 forbids the evidence tooling by name. The lane that already
// runs git writes the diff to a file, and this reads it.
[[nodiscard]] Result<ChangedLines> readUnifiedDiff(const std::filesystem::path& diffPath);

[[nodiscard]] Result<ChangedLines> parseUnifiedDiff(std::string_view bytes);

} // namespace rawframe::tool::verify
