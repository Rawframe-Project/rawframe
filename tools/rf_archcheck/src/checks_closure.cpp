#include "checks.h"
#include "text_scan.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

namespace {

// The module classes SPEC-0012 refuses in a server closure, matched on the
// identity rather than on a folder name, because a folder can be renamed and an
// accepted identity cannot.
constexpr std::array kClientOnlyMarkers{
    std::string_view{"render"},
    std::string_view{"window"},
    std::string_view{"ui"},
    std::string_view{"input"},
    std::string_view{"audio"},
    std::string_view{"studio"},
    std::string_view{"editor"},
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

bool segmentMatches(std::string_view identity, std::string_view marker) {
    std::size_t offset = 0;
    while (offset <= identity.size()) {
        const auto kDot = identity.find('.', offset);
        const auto kStop = kDot == std::string_view::npos ? identity.size() : kDot;
        if (identity.substr(offset, kStop - offset) == marker) {
            return true;
        }
        if (kDot == std::string_view::npos) {
            break;
        }
        offset = kDot + 1;
    }
    return false;
}

} // namespace

void checkNegativeClosures(const RepositoryModel& model, FindingSink& sink) {
    for (const auto& manifest : model.manifests) {
        if (!manifest.present) {
            continue;
        }
        const bool kIsTarget = manifest.path.ends_with("/target.json") || manifest.path.contains("/targets/");
        if (!kIsTarget) {
            continue;
        }
        const JsonNode* role = manifest.document.root.find("role");
        const JsonNode* identity = manifest.document.root.find("id");
        const std::string kSubject = identity != nullptr && identity->isString() ? identity->text : manifest.path;
        const std::vector<std::string> kClosure = stringArray(manifest.document.root, "resolvedClosure");
        const bool kIsServer = role != nullptr && role->isString() && role->text.contains("server");

        // RA4001: a server closure that reached a client-only class.
        if (kIsServer) {
            for (const auto& module : kClosure) {
                for (const std::string_view kMarker : kClientOnlyMarkers) {
                    if (!segmentMatches(module, kMarker)) {
                        continue;
                    }
                    sink.report(
                        "RA4001", kSubject, "the resolved server closure contains a client-only module: " + module);
                    break;
                }
            }
        }

        // RA4004: the two placements SPEC-0012 refuses by name. Loopback is a
        // local transport and cannot be in a remote artifact; the schema
        // compiler is toolchain and cannot be in a runtime one.
        const bool kIsRemote = role == nullptr || !role->isString() || !role->text.contains("loopback");
        for (const auto& module : kClosure) {
            if (module == "rawframe.network.loopback" && kIsRemote) {
                sink.report("RA4004", kSubject, "a remote artifact resolves the loopback provider: " + module);
            }
            if (module == "rawframe.schema.compiler") {
                sink.report("RA4004", kSubject, "a runtime artifact resolves the schema compiler: " + module);
            }
        }
    }

    // RA4002: a boolean that decides what a target links. SPEC-0003 puts module
    // selection in the validated profile closure, so a build file that switches
    // an edge on a cache variable has moved that authority into the build.
    std::vector<std::string> options;
    for (const auto& buildFile : model.buildLane) {
        auto text = readTextFile(model.root / buildFile);
        if (!text) {
            continue;
        }
        // The option names, read from the invocation's first argument.
        std::size_t offset = 0;
        while (offset < text->size()) {
            const auto kEnd = std::min(text->find('\n', offset), text->size());
            const std::string_view kLine(text->data() + offset, kEnd - offset);
            offset = kEnd + 1;
            const auto kStart = kLine.find("option(");
            if (kStart == std::string_view::npos) {
                continue;
            }
            std::size_t nameStart = kStart + std::string_view{"option("}.size();
            while (nameStart < kLine.size() && (kLine.at(nameStart) == ' ' || kLine.at(nameStart) == '"')) {
                ++nameStart;
            }
            std::size_t nameEnd = nameStart;
            while (nameEnd < kLine.size() && kLine.at(nameEnd) != ' ' && kLine.at(nameEnd) != '"' &&
                   kLine.at(nameEnd) != ')') {
                ++nameEnd;
            }
            if (nameEnd > nameStart) {
                options.emplace_back(kLine.substr(nameStart, nameEnd - nameStart));
            }
        }
    }
    std::ranges::sort(options);
    const auto kUnique = std::ranges::unique(options);
    options.erase(kUnique.begin(), kUnique.end());

    for (const auto& buildFile : model.buildLane) {
        auto text = readTextFile(model.root / buildFile);
        if (!text) {
            continue;
        }
        std::size_t offset = 0;
        std::size_t line = 0;
        std::size_t guardDepth = 0;
        std::size_t depth = 0;
        std::string guardName;
        while (offset < text->size()) {
            const auto kEnd = std::min(text->find('\n', offset), text->size());
            const std::string_view kLine(text->data() + offset, kEnd - offset);
            offset = kEnd + 1;
            ++line;
            if (kLine.contains("if(")) {
                ++depth;
                if (guardDepth == 0) {
                    for (const auto& option : options) {
                        if (!kLine.contains(option)) {
                            continue;
                        }
                        guardDepth = depth;
                        guardName = option;
                        break;
                    }
                }
            }
            if (guardDepth != 0 && kLine.contains("target_link_libraries")) {
                sink.reportAt(
                    "RA4002", buildFile, Position{line, 1}, "the boolean " + guardName + " decides a link edge");
            }
            if (kLine.contains("endif(")) {
                if (depth == guardDepth) {
                    guardDepth = 0;
                    guardName.clear();
                }
                depth = depth == 0 ? 0 : depth - 1;
            }
        }
    }
}

} // namespace rawframe::tool::archcheck
