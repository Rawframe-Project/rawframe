#include "checks.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

namespace {

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

} // namespace

void checkManifestProjections(const RepositoryModel& model, FindingSink& sink) {
    for (const auto& manifest : model.manifests) {
        if (!manifest.present) {
            continue;
        }

        // RA7001: a registrar table is a projection of the manifests, so the
        // only thing that makes it true is that re-deriving it produces the same
        // bytes. The manifest names the table and the modules it projects; the
        // table is read and compared, never regenerated in place.
        if (const JsonNode* registrar = manifest.document.root.find("registrarTable"); registrar != nullptr) {
            const JsonNode* path = registrar->find("path");
            const std::vector<std::string> kProjected = stringArray(*registrar, "entries");
            if (path == nullptr || !path->isString()) {
                sink.report("RA7001", manifest.path, "the registrar-table projection names no table path");
            } else if (!model.scan.hasFile(path->text)) {
                sink.report("RA7001", path->text, "the registrar table the manifest projects is absent");
            } else if (auto table = readJsonDocument(model.root / path->text); !table) {
                sink.report("RA7001", path->text, "the registrar table cannot be read: " + table.error().message);
            } else {
                const std::vector<std::string> kPresent = stringArray(table->root, "entries");
                if (kPresent != kProjected) {
                    sink.report("RA7001",
                                path->text,
                                "the registrar table is not the re-derivation of its manifest projection: it holds " +
                                    std::to_string(kPresent.size()) + " entries against " +
                                    std::to_string(kProjected.size()));
                }
            }
        }

        // RA7002: a component-schema projection covers its declared schemas
        // exactly. Exactly, in both directions: a schema the projection omits is
        // invisible to everything downstream, and a projection entry with no
        // schema behind it is a promise of data nobody wrote.
        const JsonNode* projection = manifest.document.root.find("componentSchemas");
        if (projection == nullptr || !projection->isArray()) {
            continue;
        }
        const std::string kRoot = directoryOf(manifest.path);
        std::vector<std::string> declared = stringArray(manifest.document.root, "componentSchemas");
        std::ranges::sort(declared);

        std::vector<std::string> onDisk;
        for (const auto& file : model.scan.files) {
            if (!file.path.starts_with(kRoot + "/") || !file.path.ends_with(".component.luau")) {
                continue;
            }
            onDisk.push_back(file.path);
        }
        std::ranges::sort(onDisk);

        for (const auto& entry : declared) {
            if (std::ranges::find(onDisk, entry) != onDisk.end()) {
                continue;
            }
            sink.report("RA7002", manifest.path, "the projection declares a schema that is not present: " + entry);
        }
        for (const auto& entry : onDisk) {
            if (std::ranges::find(declared, entry) != declared.end()) {
                continue;
            }
            sink.report("RA7002", entry, "a component schema exists that the projection does not cover");
        }
    }
}

} // namespace rawframe::tool::archcheck
