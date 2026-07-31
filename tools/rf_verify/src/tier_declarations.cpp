#include "tier_declarations.h"

#include "json_reader.h"
#include "repository_paths.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace rawframe::tool::verify {

namespace {

constexpr std::string_view kDeclarationFile = "tests/verification-tiers.json";

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

Result<VerificationTier> readTier(std::string_view text) {
    if (text == "O") {
        return VerificationTier::Ordinary;
    }
    if (text == "A") {
        return VerificationTier::Authority;
    }
    if (text == "H") {
        return VerificationTier::Hostile;
    }
    return reject(FailureCode::InvalidJson, {}, "a verification tier must be O, A, or H: " + std::string(text));
}

std::string directoryOf(std::string_view manifestPath) {
    const auto kSeparator = manifestPath.rfind('/');
    if (kSeparator == std::string_view::npos) {
        return {};
    }
    return std::string(manifestPath.substr(0, kSeparator));
}

Result<std::vector<std::string>> listedManifests(const std::filesystem::path& repositoryRoot) {
    auto index = readJsonFile(repositoryRoot / "repository.json");
    if (!index) {
        return std::unexpected(index.error());
    }
    std::vector<std::string> roots;
    for (const std::string_view kArray : {"tools", "modules"}) {
        const JsonNode* array = index->find(kArray);
        if (array == nullptr || !array->isArray()) {
            return reject(FailureCode::InvalidJson, "repository.json", "a membership array is absent or not an array");
        }
        for (const auto& entry : array->elements) {
            if (!entry.isString()) {
                return reject(FailureCode::InvalidJson, "repository.json", "a membership entry is not a path");
            }
            auto root = directoryOf(entry.text);
            if (root.empty()) {
                return reject(
                    FailureCode::InvalidJson, "repository.json", "a membership entry has no root: " + entry.text);
            }
            roots.push_back(std::move(root));
        }
    }
    std::ranges::sort(roots);
    const auto kRemoved = std::ranges::unique(roots);
    roots.erase(kRemoved.begin(), kRemoved.end());
    return roots;
}

Status collectPresentUnits(const std::filesystem::path& repositoryRoot,
                           std::string_view declaringRoot,
                           std::vector<std::string>& present) {
    for (const std::string_view kSubdirectory : {"src", "include"}) {
        const auto kBase = repositoryRoot / std::filesystem::path(declaringRoot) / std::filesystem::path(kSubdirectory);
        // `exists` reports false whenever it sets the error code, so a second
        // test on the error would be an operand that can never decide this on
        // its own. A root that cannot be read is skipped here and reported by
        // the iteration below if it holds anything.
        std::error_code error;
        if (!std::filesystem::exists(kBase, error)) {
            continue;
        }
        for (std::filesystem::recursive_directory_iterator iterator(kBase, error), end; iterator != end;
             iterator.increment(error)) {
            if (error) {
                return reject(FailureCode::IoFailure, kBase.generic_string(), "a declared source root cannot be read");
            }
            if (!iterator->is_regular_file(error)) {
                continue;
            }
            auto relative = repositoryRelative(repositoryRoot, iterator->path().generic_string());
            if (!relative) {
                return std::unexpected(relative.error());
            }
            if (isMaintainedSourceUnit(*relative)) {
                present.push_back(*relative);
            }
        }
    }
    return {};
}

} // namespace

Result<std::vector<TierDeclaration>> readTierDeclarationFile(const std::filesystem::path& path,
                                                             std::string_view declaringRoot) {
    auto document = readJsonFile(path);
    if (!document) {
        return std::unexpected(document.error());
    }
    const JsonNode* units = document->find("units");
    if (units == nullptr || !units->isArray()) {
        return reject(FailureCode::InvalidJson, path.generic_string(), "the declaration has no units array");
    }

    std::vector<TierDeclaration> declarations;
    for (const auto& entry : units->elements) {
        const JsonNode* unitPath = entry.find("path");
        const JsonNode* tier = entry.find("tier");
        const JsonNode* reason = entry.find("reason");
        if (unitPath == nullptr || !unitPath->isString() || tier == nullptr || !tier->isString() || reason == nullptr ||
            !reason->isString()) {
            return reject(FailureCode::InvalidJson,
                          path.generic_string(),
                          "a unit declaration needs a path, a tier, and a reason");
        }
        auto resolved = readTier(tier->text);
        if (!resolved) {
            Failure failure = resolved.error();
            failure.path = path.generic_string();
            return std::unexpected(failure);
        }
        TierDeclaration declaration;
        declaration.path = std::string(declaringRoot) + "/" + unitPath->text;
        declaration.tier = *resolved;
        declaration.reason = reason->text;
        declaration.source = std::string(declaringRoot) + "/" + std::string(kDeclarationFile);
        declarations.push_back(std::move(declaration));
    }
    return declarations;
}

Result<TierIndex> readTierIndex(const std::filesystem::path& repositoryRoot) {
    auto roots = listedManifests(repositoryRoot);
    if (!roots) {
        return std::unexpected(roots.error());
    }

    TierIndex index;
    std::vector<std::string> present;
    for (const auto& root : *roots) {
        const auto kDeclarationPath =
            repositoryRoot / std::filesystem::path(root) / std::filesystem::path(kDeclarationFile);
        std::error_code error;
        const bool kHasSource = std::filesystem::exists(repositoryRoot / std::filesystem::path(root) / "src", error);
        if (!std::filesystem::exists(kDeclarationPath, error)) {
            if (!kHasSource) {
                continue;
            }
            return reject(FailureCode::MissingInput,
                          root + "/" + std::string(kDeclarationFile),
                          "a listed root with maintained source declares no verification tiers");
        }
        auto declarations = readTierDeclarationFile(kDeclarationPath, root);
        if (!declarations) {
            return std::unexpected(declarations.error());
        }
        for (auto& declaration : *declarations) {
            auto existing = index.units.find(declaration.path);
            if (existing != index.units.end()) {
                return reject(
                    FailureCode::InvalidJson, declaration.path, "two declarations claim the same source unit");
            }
            index.units.emplace(declaration.path, std::move(declaration));
        }
        if (auto status = collectPresentUnits(repositoryRoot, root, present); !status) {
            return std::unexpected(status.error());
        }
    }

    for (const auto& unit : present) {
        if (!index.units.contains(unit)) {
            index.presentButUndeclared.push_back(unit);
        }
    }
    for (const auto& [path, declaration] : index.units) {
        if (std::ranges::find(present, path) == present.end()) {
            index.declaredButAbsent.push_back(path);
        }
    }
    std::ranges::sort(index.presentButUndeclared);
    std::ranges::sort(index.declaredButAbsent);
    return index;
}

} // namespace rawframe::tool::verify
