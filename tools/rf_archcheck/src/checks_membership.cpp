#include "checks.h"
#include "text_scan.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

namespace rawframe::tool::archcheck {

namespace {

// The exact first production inventory ADR-0012 accepts. It is written out
// rather than derived, because the point of the rule is that a module identity
// nobody accepted cannot appear, and a list derived from the repository would
// accept whatever the repository already contains.
constexpr std::array kAcceptedModules{
    std::string_view{"rawframe.base"},
    std::string_view{"rawframe.result"},
    std::string_view{"rawframe.diagnostics"},
    std::string_view{"rawframe.execution"},
    std::string_view{"rawframe.composition"},
    std::string_view{"rawframe.schema"},
    std::string_view{"rawframe.world"},
    std::string_view{"rawframe.content"},
    std::string_view{"rawframe.luau"},
    std::string_view{"rawframe.network"},
    std::string_view{"rawframe.world.snapshot"},
    std::string_view{"rawframe.world.luau"},
    std::string_view{"rawframe.world.replication"},
    std::string_view{"rawframe.network.loopback"},
    std::string_view{"rawframe.network.quic"},
    std::string_view{"rawframe.schema.compiler"},
    std::string_view{"rawframe.host.dedicated_server"},
};

constexpr std::array kForbiddenNames{
    std::string_view{"core"},
    std::string_view{"common"},
    std::string_view{"shared"},
    std::string_view{"misc"},
    std::string_view{"helpers"},
    std::string_view{"utils"},
    std::string_view{"util"},
    std::string_view{"managers"},
    std::string_view{"manager"},
    std::string_view{"engine"},
};

constexpr std::array kDiscoveryCommands{
    std::string_view{"aux_source_directory"},
    std::string_view{"subdirs"},
};

std::string directoryOf(std::string_view path) {
    const auto kSlash = path.find_last_of('/');
    if (kSlash == std::string_view::npos) {
        return {};
    }
    return std::string(path.substr(0, kSlash));
}

std::string_view lastSegment(std::string_view identifier) {
    const auto kDot = identifier.find_last_of('.');
    return kDot == std::string_view::npos ? identifier : identifier.substr(kDot + 1);
}

} // namespace

void checkMembershipReality(const RepositoryModel& model, FindingSink& sink) {
    const MembershipArray* modules = model.membershipArray("modules");

    // RA2001: a listed root that is not there.
    if (modules != nullptr) {
        for (const auto& entry : modules->entries) {
            const std::string kRoot = directoryOf(entry);
            if (kRoot.empty() || !model.scan.hasDirectory(kRoot)) {
                sink.report("RA2001", entry, "the listed module root is absent from the tree: " + kRoot);
            }
        }
    }

    // RA2002: a module root on disk that nothing lists. A directory holding a
    // module manifest is a module by construction, so the manifest is what makes
    // it discoverable and the index is what has to admit it.
    for (const auto& file : model.scan.files) {
        if (!file.path.ends_with("/module.json")) {
            continue;
        }
        const bool kListed =
            modules != nullptr && std::ranges::find(modules->entries, file.path) != modules->entries.end();
        if (!kListed) {
            sink.report("RA2002", file.path, "a module manifest exists that the root index does not list");
        }
    }

    // RA2003: a build file that discovers its own subjects.
    for (const auto& buildFile : model.buildLane) {
        auto text = readTextFile(model.root / buildFile);
        if (!text) {
            continue;
        }
        for (const std::string_view kCommand : kDiscoveryCommands) {
            for (const auto& match : findCommandInvocations(*text, kCommand)) {
                sink.reportAt("RA2003",
                              buildFile,
                              match.position,
                              "the build file discovers its subjects with " + std::string(kCommand));
            }
        }
    }

    // RA2004 and RA2005: what a listed module claims to be.
    for (const auto& manifest : model.manifests) {
        if (!manifest.present || !manifest.path.ends_with("/module.json")) {
            continue;
        }
        const JsonNode* id = manifest.document.root.find("id");
        if (id == nullptr || !id->isString()) {
            continue;
        }
        const bool kAccepted = std::ranges::any_of(kAcceptedModules, [id](std::string_view accepted) {
            return accepted == id->text;
        });
        if (!kAccepted) {
            sink.report(
                "RA2004", manifest.path, "the module identity is outside the accepted first inventory: " + id->text);
        }
        const std::string_view kSegment = lastSegment(id->text);
        const bool kForbidden = std::ranges::any_of(kForbiddenNames, [kSegment](std::string_view forbidden) {
            return forbidden == kSegment;
        });
        if (kForbidden) {
            sink.report("RA2005", manifest.path, "the module name is a catch-all: " + std::string(kSegment));
        }
    }

    // RA2006: a tool the index does not list. Explicit membership is the whole
    // of ADR-0022's tool admission, so a manifest that exists without an entry
    // is a tool that arrived by being found.
    const MembershipArray* tools = model.membershipArray("tools");
    for (const auto& file : model.scan.files) {
        if (!file.path.ends_with("/tool.json") || !file.path.starts_with("tools/")) {
            continue;
        }
        const bool kListed = tools != nullptr && std::ranges::find(tools->entries, file.path) != tools->entries.end();
        if (!kListed) {
            sink.report("RA2006", file.path, "a tool manifest exists that the root index does not list");
        }
    }
}

} // namespace rawframe::tool::archcheck
