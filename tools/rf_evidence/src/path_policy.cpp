#include "path_policy.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace rawframe::tool::evidence {

namespace {

bool containsForbiddenComponent(std::string_view path) {
    if (path.empty() || path.size() > 1'024 || path.front() == '/' || path.contains('\\')) {
        return true;
    }

    std::size_t components = 0;
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto kEnd = path.find('/', start);
        const auto kComponent = path.substr(start, kEnd == std::string_view::npos ? path.size() - start : kEnd - start);
        ++components;
        if (kComponent.empty() || kComponent == "." || kComponent == ".." || kComponent.size() > 128) {
            return true;
        }
        if (kEnd == std::string_view::npos) {
            break;
        }
        start = kEnd + 1;
    }
    return components > 128;
}

} // namespace

Result<std::filesystem::path> resolveRepositoryPath(const std::filesystem::path& repositoryRoot,
                                                    std::string_view relativePath) {
    if (containsForbiddenComponent(relativePath)) {
        return std::unexpected(Failure{
            FailureCode::InvalidPath, std::string(relativePath), "path is not a safe repository-relative path"});
    }

    const std::filesystem::path kCandidate = repositoryRoot / std::filesystem::path(relativePath);
    std::error_code error;
    const auto kCanonicalRoot = std::filesystem::weakly_canonical(repositoryRoot, error);
    if (error) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, repositoryRoot.generic_string(), "failed to resolve repository root"});
    }
    auto canonicalCandidate = std::filesystem::weakly_canonical(kCandidate, error);
    if (error) {
        return std::unexpected(
            Failure{FailureCode::InvalidPath, std::string(relativePath), "failed to resolve repository path"});
    }

    const auto kRootText = portableLowercasePath(kCanonicalRoot);
    const auto kCandidateText = portableLowercasePath(canonicalCandidate);
    const auto kRootPrefix = kRootText.ends_with('/') ? kRootText : kRootText + '/';
    if (kCandidateText != kRootText && !kCandidateText.starts_with(kRootPrefix)) {
        return std::unexpected(
            Failure{FailureCode::InvalidPath, std::string(relativePath), "resolved path escapes the repository"});
    }
    return canonicalCandidate;
}

std::string portableLowercasePath(const std::filesystem::path& path) {
    auto value = path.lexically_normal().generic_string();
    std::ranges::transform(value, value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

} // namespace rawframe::tool::evidence
