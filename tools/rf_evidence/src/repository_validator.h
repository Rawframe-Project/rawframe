#pragma once

#include "failure.h"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

struct ToolInfo {
    std::string id;
    std::string manifestPath;
    std::string owner;
    std::string cmakeTarget;
    std::vector<std::string> thirdPartyDependencies;
    std::vector<std::string> managedToolDependencies;
};

// One maintained evidence authority as the registered index names it. SPEC-0017
// forbids discovering these by scanning, so this is the only statement that a
// given file is part of the repository at all.
struct EvidenceAuthorityInfo {
    std::string authorityClass;
    std::string path;
    std::string mediaType;
};

struct RepositorySnapshot {
    std::filesystem::path root;
    std::vector<ToolInfo> tools;
    std::string evidenceIndexPath;
    std::vector<EvidenceAuthorityInfo> evidenceAuthorities;
};

[[nodiscard]] Result<RepositorySnapshot> validateRepository(const std::filesystem::path& repositoryRoot);

// The two halves of evidence membership, separately reachable so that each can
// be proven against a root built for the purpose. Repository validation runs
// both; a caller that ran only the first would hold a list it had not shown to
// be complete.
//
// The first reads the index and proves every entry resolves inside the
// repository, is an ordinary file, and agrees with itself. The second proves
// the tree holds nothing the index does not claim, which is the one failure a
// membership list cannot report by reading itself.
[[nodiscard]] Result<std::vector<EvidenceAuthorityInfo>>
readEvidenceAuthorities(const std::filesystem::path& repositoryRoot, const std::filesystem::path& indexPath);

[[nodiscard]] Status rejectUnlistedEvidenceAuthorities(const std::filesystem::path& repositoryRoot,
                                                       std::string_view indexRelativePath,
                                                       const std::vector<EvidenceAuthorityInfo>& authorities);

} // namespace rawframe::tool::evidence
