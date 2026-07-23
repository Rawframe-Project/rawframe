#include "source_inspector.h"

#include "path_policy.h"

#include <algorithm>
#include <fstream>

namespace rawframe::tool::evidence {

Result<std::vector<SourceOwnershipEntry>> inspectSourceOwnership(const std::filesystem::path& repositoryRoot) {
    auto sourceRoot = resolveRepositoryPath(repositoryRoot, "tools/rf_evidence");
    if (!sourceRoot) {
        return std::unexpected(sourceRoot.error());
    }

    std::vector<SourceOwnershipEntry> entries;
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(*sourceRoot, error), end; iterator != end;
         iterator.increment(error)) {
        if (error) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, sourceRoot->generic_string(), "failed to enumerate maintained source"});
        }
        if (iterator->is_symlink(error)) {
            return std::unexpected(Failure{FailureCode::InvalidPath,
                                           iterator->path().generic_string(),
                                           "symlinks are forbidden in maintained tool source"});
        }
        if (!iterator->is_regular_file(error)) {
            continue;
        }

        const auto kExtension = iterator->path().extension().string();
        const auto kFilename = iterator->path().filename().string();
        if (kExtension != ".cpp" && kExtension != ".h" && kExtension != ".json" && kFilename != "CMakeLists.txt") {
            continue;
        }

        std::ifstream input(iterator->path(), std::ios::binary);
        if (!input) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, iterator->path().generic_string(), "failed to read maintained source"});
        }
        std::size_t lines = 0;
        std::string line;
        while (std::getline(input, line)) {
            ++lines;
        }
        if (lines >= 1'500) {
            return std::unexpected(Failure{FailureCode::LimitExceeded,
                                           iterator->path().generic_string(),
                                           "source file reaches the 1500-line hard failure gate"});
        }

        const auto kRelative = std::filesystem::relative(iterator->path(), repositoryRoot, error).generic_string();
        if (error) {
            return std::unexpected(Failure{FailureCode::IoFailure,
                                           iterator->path().generic_string(),
                                           "failed to calculate source ownership path"});
        }
        entries.push_back(SourceOwnershipEntry{kRelative, lines, "rawframe.build_engineering"});
    }

    std::ranges::sort(entries, {}, &SourceOwnershipEntry::path);
    return entries;
}

} // namespace rawframe::tool::evidence
