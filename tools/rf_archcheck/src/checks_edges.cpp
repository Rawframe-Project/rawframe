#include "checks.h"
#include "text_scan.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace rawframe::tool::archcheck {

namespace {

std::string directoryOf(std::string_view path) {
    const auto kSlash = path.find_last_of('/');
    if (kSlash == std::string_view::npos) {
        return {};
    }
    return std::string(path.substr(0, kSlash));
}

struct ModuleManifest {
    std::string manifestPath;
    std::string root;
    std::string id;
    // Declared edges by category, in the categories SPEC-0007 names.
    std::map<std::string, std::vector<std::string>> edges;
};

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

std::vector<ModuleManifest> collectModules(const RepositoryModel& model) {
    std::vector<ModuleManifest> modules;
    for (const auto& manifest : model.manifests) {
        if (!manifest.present || !manifest.path.ends_with("/module.json")) {
            continue;
        }
        ModuleManifest module;
        module.manifestPath = manifest.path;
        module.root = directoryOf(manifest.path);
        if (const JsonNode* id = manifest.document.root.find("id"); id != nullptr && id->isString()) {
            module.id = id->text;
        }
        if (const JsonNode* dependencies = manifest.document.root.find("dependencies"); dependencies != nullptr) {
            for (const std::string_view kCategory : {"public", "private", "test", "tool", "hostOnly"}) {
                module.edges[std::string(kCategory)] = stringArray(*dependencies, kCategory);
            }
        }
        modules.push_back(std::move(module));
    }
    return modules;
}

// The module a first-party include names. Public headers live under
// `include/rawframe/<module path>/`, so the include target carries the owner.
std::string moduleOfInclude(std::string_view target, const std::vector<ModuleManifest>& modules) {
    if (!target.starts_with("rawframe/")) {
        return {};
    }
    std::string best;
    for (const auto& module : modules) {
        std::string prefix = "rawframe/";
        for (const char kCharacter : module.id) {
            prefix.push_back(kCharacter == '.' ? '/' : kCharacter);
        }
        // `rawframe.base` becomes `rawframe/rawframe/base`, so the leading
        // component of the identity is dropped before the comparison.
        const auto kSecond = prefix.find('/', std::string_view{"rawframe/"}.size());
        if (kSecond != std::string::npos) {
            prefix = "rawframe/" + prefix.substr(kSecond + 1);
        }
        prefix.push_back('/');
        if (target.starts_with(prefix) && prefix.size() > best.size()) {
            best = module.id;
        }
    }
    return best;
}

bool declares(const ModuleManifest& module, std::string_view id) {
    return std::ranges::any_of(module.edges, [id](const auto& category) {
        return std::ranges::find(category.second, id) != category.second.end();
    });
}

bool hasCycle(const std::vector<ModuleManifest>& modules, std::string& cycleAt) {
    std::map<std::string, std::vector<std::string>> graph;
    for (const auto& module : modules) {
        for (const auto& category : module.edges) {
            if (category.first == "test" || category.first == "tool") {
                continue;
            }
            for (const auto& edge : category.second) {
                graph[module.id].push_back(edge);
            }
        }
    }
    std::set<std::string> visiting;
    std::set<std::string> done;
    const auto kVisit = [&](const std::string& node, auto&& self) -> bool {
        if (done.contains(node)) {
            return false;
        }
        if (!visiting.insert(node).second) {
            cycleAt = node;
            return true;
        }
        for (const auto& next : graph[node]) {
            if (self(next, self)) {
                return true;
            }
        }
        visiting.erase(node);
        done.insert(node);
        return false;
    };
    return std::ranges::any_of(modules, [&kVisit](const ModuleManifest& module) {
        return kVisit(module.id, kVisit);
    });
}

} // namespace

void checkDependencyEdges(const RepositoryModel& model, FindingSink& sink) {
    const std::vector<ModuleManifest> kModules = collectModules(model);

    for (const auto& module : kModules) {
        for (const auto& file : model.scan.files) {
            if (!file.path.starts_with(module.root + "/") || !isFirstPartySource(file.path)) {
                continue;
            }
            const bool kIsTest = file.path.contains("/tests/");
            auto text = readTextFile(model.root / file.path);
            if (!text) {
                continue;
            }
            const bool kIsPublicHeader = file.path.contains("/include/");
            for (const auto& include : findIncludes(*text)) {
                const std::string kOwner = moduleOfInclude(include.target, kModules);
                if (kOwner.empty() || kOwner == module.id) {
                    continue;
                }
                // RA3001: the include exists and the manifest does not say so.
                if (!declares(module, kOwner)) {
                    sink.reportAt("RA3001",
                                  file.path,
                                  include.position,
                                  "the source includes " + include.target + ", owned by " + kOwner +
                                      ", and the manifest declares no edge to it");
                    continue;
                }
                // RA3002: the edge is declared, in a category the use
                // contradicts. A private edge cannot appear in a public header
                // and a test edge cannot appear in shipped source.
                const auto& kPublic = module.edges.at("public");
                const auto& kTest = module.edges.at("test");
                if (kIsPublicHeader && std::ranges::find(kPublic, kOwner) == kPublic.end()) {
                    sink.reportAt("RA3002",
                                  file.path,
                                  include.position,
                                  "a public header includes " + include.target + " through a non-public edge to " +
                                      kOwner);
                }
                if (!kIsTest && std::ranges::find(kTest, kOwner) != kTest.end() &&
                    std::ranges::find(kPublic, kOwner) == kPublic.end()) {
                    sink.reportAt("RA3002",
                                  file.path,
                                  include.position,
                                  "non-test source includes " + include.target + " through a test edge to " + kOwner);
                }
            }
        }
    }

    // RA3003: layering. A cycle is the one violation that is decidable without
    // a layer table, and the accepted graph is a DAG, so a cycle is enough to
    // refuse without inventing a layer order.
    std::string cycleAt;
    if (hasCycle(kModules, cycleAt)) {
        sink.report("RA3003", cycleAt, "the production module graph is not acyclic at: " + cycleAt);
    }

    // RA3004: an edge a build file introduces and the manifest does not carry.
    for (const auto& module : kModules) {
        const std::string kBuildFile = module.root + "/CMakeLists.txt";
        if (!model.scan.hasFile(kBuildFile)) {
            continue;
        }
        auto text = readTextFile(model.root / kBuildFile);
        if (!text) {
            continue;
        }
        for (const auto& other : kModules) {
            if (other.id == module.id) {
                continue;
            }
            std::string linked = "rawframe::";
            const auto kDot = other.id.find('.');
            linked += kDot == std::string::npos ? other.id : other.id.substr(kDot + 1);
            for (const auto& match : findLiteral(*text, linked)) {
                if (declares(module, other.id)) {
                    continue;
                }
                sink.reportAt("RA3004",
                              kBuildFile,
                              match.position,
                              "the build file links " + linked + " and the manifest declares no edge to " + other.id);
            }
        }
    }

    // RA3005: the same truth written twice. The duplication ADR-0004 forbids is
    // the edge, so the subject is a line that declares one. A build file that
    // reads a locked object by its key is consuming an authority rather than
    // becoming one, and naming a key is not naming an edge.
    for (const auto& buildFile : model.buildLane) {
        auto text = readTextFile(model.root / buildFile);
        if (!text) {
            continue;
        }
        for (const std::string_view kDeclaring :
             {std::string_view{"target_link_libraries"}, std::string_view{"find_package"}}) {
            for (const auto& declaration : findCommandInvocations(*text, kDeclaring)) {
                const std::string_view kLine = lineAt(*text, declaration.position.line);
                for (const auto& entry : model.catalog) {
                    if (!kLine.contains(entry.id)) {
                        continue;
                    }
                    sink.reportAt("RA3005",
                                  buildFile,
                                  declaration.position,
                                  "the build file declares an edge by the catalog identity " + entry.id);
                }
                for (const auto& module : kModules) {
                    if (!kLine.contains(module.id)) {
                        continue;
                    }
                    sink.reportAt("RA3005",
                                  buildFile,
                                  declaration.position,
                                  "the build file declares an edge by the module identity " + module.id);
                }
            }
        }
    }
}

} // namespace rawframe::tool::archcheck
