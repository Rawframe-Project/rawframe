#include "source_inspector.h"

#include "repository_validator.h"

#include <algorithm>
#include <fstream>

namespace rawframe::tool::evidence {
namespace {

// STD-0001 measures physical lines. A final line without a trailing terminator
// is still extracted by getline and therefore still counted.
Result<std::size_t> countPhysicalLines(const std::filesystem::path& file) {
    std::ifstream input(file, std::ios::binary);
    if (!input) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, file.generic_string(), "failed to read maintained source"});
    }
    std::size_t lines = 0;
    std::string line;
    while (std::getline(input, line)) {
        ++lines;
    }
    return lines;
}

bool isMaintainedSourceName(const std::filesystem::path& file) {
    const auto kExtension = file.extension().string();
    const auto kFilename = file.filename().string();
    return kExtension == ".cpp" || kExtension == ".h" || kExtension == ".json" || kFilename == "CMakeLists.txt";
}

Status inspectToolRoot(const std::filesystem::path& repositoryRoot,
                       const std::filesystem::path& toolRoot,
                       const std::string& owner,
                       std::vector<SourceOwnershipEntry>& entries) {
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(toolRoot, error), end; iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, toolRoot.generic_string(), "failed to enumerate maintained source"});
        }
        if (iterator->is_symlink(error)) {
            return std::unexpected(Failure{FailureCode::InvalidPath,
                                           iterator->path().generic_string(),
                                           "symlinks are forbidden in maintained tool source"});
        }
        if (!iterator->is_regular_file(error) || !isMaintainedSourceName(iterator->path())) {
            continue;
        }

        auto lines = countPhysicalLines(iterator->path());
        if (!lines) {
            return std::unexpected(lines.error());
        }
        if (auto admitted = admitPhysicalLineCount(iterator->path().generic_string(), *lines); !admitted) {
            return std::unexpected(admitted.error());
        }

        const auto kRelative = std::filesystem::relative(iterator->path(), repositoryRoot, error).generic_string();
        if (error) {
            return std::unexpected(Failure{FailureCode::IoFailure,
                                           iterator->path().generic_string(),
                                           "failed to calculate source ownership path"});
        }
        entries.push_back(SourceOwnershipEntry{kRelative, *lines, owner, sourceGateForLines(*lines)});
    }
    return {};
}

} // namespace

Status admitPhysicalLineCount(std::string_view path, std::size_t lines) {
    if (lines >= kHardFailureLines) {
        return std::unexpected(Failure{FailureCode::LimitExceeded,
                                       std::string{path},
                                       "source file reaches the 1500-line hard failure gate"});
    }
    return {};
}

Result<std::vector<SourceOwnershipEntry>> inspectSourceOwnership(const std::filesystem::path& repositoryRoot) {
    // Membership and ownership both come from the validated repository snapshot.
    // Scanning `tools/` directly would infer membership from a directory, which
    // ADR-0022 forbids, and would leave the owner as an unsourced constant.
    auto snapshot = validateRepository(repositoryRoot);
    if (!snapshot) {
        return std::unexpected(snapshot.error());
    }

    std::vector<SourceOwnershipEntry> entries;
    for (const auto& tool : snapshot->tools) {
        const auto kManifest = repositoryRoot / std::filesystem::path(tool.manifestPath);
        if (auto status = inspectToolRoot(repositoryRoot, kManifest.parent_path(), tool.owner, entries); !status) {
            return std::unexpected(status.error());
        }
    }

    std::ranges::sort(entries, {}, &SourceOwnershipEntry::path);
    return entries;
}

} // namespace rawframe::tool::evidence
