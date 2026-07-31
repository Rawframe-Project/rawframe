#include "repository_model.h"

#include "tool_limits.h"

#include <algorithm>
#include <array>
#include <utility>

namespace rawframe::tool::archcheck {

namespace {

constexpr std::array kMembershipNames{
    std::string_view{"modules"},
    std::string_view{"targets"},
    std::string_view{"platforms"},
    std::string_view{"configurations"},
    std::string_view{"instrumentations"},
    std::string_view{"packagingPolicies"},
    std::string_view{"profiles"},
    std::string_view{"tools"},
};

LoadedManifest loadManifest(const std::filesystem::path& root, std::string path) {
    LoadedManifest manifest;
    manifest.path = std::move(path);
    auto document = readJsonDocument(root / manifest.path);
    if (!document) {
        manifest.readFailure = document.error().message;
        return manifest;
    }
    manifest.present = true;
    manifest.document = std::move(*document);
    return manifest;
}

std::vector<std::string> stringArray(const JsonNode& parent, std::string_view key) {
    std::vector<std::string> values;
    const JsonNode* node = parent.find(key);
    if (node == nullptr || !node->isArray()) {
        return values;
    }
    for (const auto& element : node->elements) {
        if (element.isString()) {
            values.push_back(element.text);
        }
    }
    return values;
}

std::string directoryOf(std::string_view path) {
    const auto kSlash = path.find_last_of('/');
    if (kSlash == std::string_view::npos) {
        return {};
    }
    return std::string(path.substr(0, kSlash));
}

// The build lane is whatever the root build file reaches, followed rather than
// listed. `include(<module>)` without a path is a CMake module and not a
// repository file, so it contributes nothing.
void followBuildLane(const std::filesystem::path& root,
                     const std::string& relativePath,
                     std::vector<std::string>& lane) {
    if (std::ranges::find(lane, relativePath) != lane.end()) {
        return;
    }
    if (lane.size() >= kMaximumScannedFiles) {
        return;
    }
    lane.push_back(relativePath);
    auto text = readTextFile(root / relativePath);
    if (!text) {
        return;
    }
    const std::string kBase = directoryOf(relativePath);
    std::size_t offset = 0;
    while (offset < text->size()) {
        const auto kEnd = std::min(text->find('\n', offset), text->size());
        std::string_view line(text->data() + offset, kEnd - offset);
        offset = kEnd + 1;
        const auto kComment = line.find('#');
        if (kComment != std::string_view::npos) {
            line = line.substr(0, kComment);
        }
        for (const std::string_view kCommand : {std::string_view{"include("}, std::string_view{"add_subdirectory("}}) {
            const auto kStart = line.find(kCommand);
            if (kStart == std::string_view::npos) {
                continue;
            }
            const auto kOpen = kStart + kCommand.size();
            const auto kClose = line.find(')', kOpen);
            if (kClose == std::string_view::npos) {
                continue;
            }
            std::string argument(line.substr(kOpen, kClose - kOpen));
            while (!argument.empty() && (argument.front() == ' ' || argument.front() == '"')) {
                argument.erase(argument.begin());
            }
            while (!argument.empty() && (argument.back() == ' ' || argument.back() == '"')) {
                argument.pop_back();
            }
            if (argument.empty() || argument.contains('$') || argument.contains(' ')) {
                continue;
            }
            std::string candidate = kBase;
            if (!candidate.empty()) {
                candidate += "/";
            }
            candidate += argument;
            if (kCommand == "add_subdirectory(") {
                candidate += "/CMakeLists.txt";
            } else if (!candidate.ends_with(".cmake")) {
                // A bare module name, resolved by CMake's own module path.
                continue;
            }
            followBuildLane(root, candidate, lane);
        }
    }
}

} // namespace

const MembershipArray* RepositoryModel::membershipArray(std::string_view name) const noexcept {
    for (const auto& array : membership) {
        if (array.name == name) {
            return &array;
        }
    }
    return nullptr;
}

Result<RepositoryModel> loadRepositoryModel(const std::filesystem::path& root, std::string_view corpusRelativePath) {
    auto scan = scanRepository(root);
    if (!scan) {
        return std::unexpected(scan.error());
    }

    RepositoryModel model;
    model.root = root;
    model.scan = std::move(*scan);
    model.corpusPath = std::string(corpusRelativePath);

    model.index = loadManifest(root, "repository.json");
    if (!model.index.present) {
        return std::unexpected(
            Failure{FailureCode::MissingInput,
                    "repository.json",
                    "the repository index cannot be read, so nothing can be concluded about the repository"});
    }
    model.manifests.push_back(model.index);

    for (const std::string_view kName : kMembershipNames) {
        MembershipArray array;
        array.name = std::string(kName);
        array.entries = stringArray(model.index.document.root, kName);
        model.membership.push_back(std::move(array));
    }
    if (const JsonNode* evidenceIndex = model.index.document.root.find("evidenceIndex");
        evidenceIndex != nullptr && evidenceIndex->isString()) {
        model.evidenceIndexPath = evidenceIndex->text;
    }

    for (const auto& array : model.membership) {
        for (const auto& entry : array.entries) {
            if (std::ranges::any_of(model.manifests, [&entry](const LoadedManifest& held) {
                    return held.path == entry;
                })) {
                continue;
            }
            LoadedManifest manifest = loadManifest(root, entry);
            // A manifest that is there and cannot be parsed is not a finding.
            // Nothing can be concluded about a repository whose declared
            // authority the tool cannot read, and reporting the rules that
            // happened to survive would be a clean-looking partial answer.
            if (!manifest.present && model.scan.hasFile(entry)) {
                return std::unexpected(
                    Failure{FailureCode::InvalidJson,
                            entry,
                            "a listed manifest is present and cannot be parsed: " + manifest.readFailure});
            }
            model.manifests.push_back(std::move(manifest));
        }
    }

    for (const auto& manifest : model.manifests) {
        const bool kIsTool = std::ranges::any_of(model.membership, [&manifest](const MembershipArray& array) {
            return array.name == "tools" && std::ranges::find(array.entries, manifest.path) != array.entries.end();
        });
        if (!kIsTool || !manifest.present) {
            continue;
        }
        ToolManifest tool;
        tool.manifestPath = manifest.path;
        tool.root = directoryOf(manifest.path);
        if (const JsonNode* id = manifest.document.root.find("id"); id != nullptr && id->isString()) {
            tool.id = id->text;
        }
        if (const JsonNode* implementation = manifest.document.root.find("implementation"); implementation != nullptr) {
            if (const JsonNode* target = implementation->find("cmakeTarget"); target != nullptr && target->isString()) {
                tool.cmakeTarget = target->text;
            }
        }
        if (const JsonNode* dependencies = manifest.document.root.find("dependencies"); dependencies != nullptr) {
            tool.thirdParty = stringArray(*dependencies, "thirdParty");
            tool.managedTools = stringArray(*dependencies, "managedTools");
        }
        model.tools.push_back(std::move(tool));
    }

    // The catalog is read but never judged: `rf-evidence` owns its agreement
    // with the licence index and the locks. It is here because a rule about a
    // vendored entry has to know which entries claim to be vendored.
    if (auto catalog = readJsonDocument(root / "third_party/catalog.json"); catalog) {
        if (const JsonNode* entries = catalog->root.find("entries"); entries != nullptr && entries->isArray()) {
            for (const auto& element : entries->elements) {
                CatalogEntry entry;
                if (const JsonNode* id = element.find("id"); id != nullptr && id->isString()) {
                    entry.id = id->text;
                }
                if (const JsonNode* acquisition = element.find("acquisitionClass");
                    acquisition != nullptr && acquisition->isString()) {
                    entry.acquisitionClass = acquisition->text;
                }
                if (const JsonNode* provider = element.find("provider"); provider != nullptr) {
                    if (const JsonNode* type = provider->find("type"); type != nullptr && type->isString()) {
                        entry.providerType = type->text;
                    }
                    if (const JsonNode* reference = provider->find("reference");
                        reference != nullptr && reference->isString()) {
                        entry.providerReference = reference->text;
                    }
                }
                model.catalog.push_back(std::move(entry));
            }
        }
    }

    if (!model.corpusPath.empty() && model.scan.hasFile(model.corpusPath)) {
        model.manifests.push_back(loadManifest(root, model.corpusPath));
    }

    followBuildLane(root, "CMakeLists.txt", model.buildLane);
    std::ranges::sort(model.buildLane);

    return model;
}

} // namespace rawframe::tool::archcheck
