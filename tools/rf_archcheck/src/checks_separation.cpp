#include "checks.h"
#include "text_scan.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

namespace {

// The one declared generated root. It is declared by every tool manifest's
// output root pattern and by the repository's own ignore rules, so a generated
// file anywhere else is generated material that escaped its root.
constexpr std::string_view kGeneratedRoot = "out/";

constexpr std::array kVendorOriginMembers{
    std::string_view{"catalogId"},
    std::string_view{"upstreamProject"},
    std::string_view{"version"},
    std::string_view{"revision"},
    std::string_view{"sourceUrl"},
    std::string_view{"sha256"},
    std::string_view{"licenseReference"},
    std::string_view{"importedPaths"},
    std::string_view{"importProcedure"},
    std::string_view{"patches"},
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

} // namespace

void checkGeneratedAndVendoredSeparation(const RepositoryModel& model, FindingSink& sink) {
    // RA6001: a file in the maintained tree that says it was generated. The scan
    // never enters the generated root, so every subject here is by construction
    // outside it, and the file's own banner is the evidence.
    for (const auto& file : model.scan.files) {
        const std::string_view kExtension = fileExtension(file.path);
        const bool kInspectable = kExtension == ".cpp" || kExtension == ".h" || kExtension == ".cmake" ||
                                  kExtension == ".json" || kExtension == ".luau" || kExtension == ".txt";
        if (!kInspectable || file.path.starts_with("third_party/")) {
            continue;
        }
        auto text = readTextFile(model.root / file.path);
        if (!text) {
            continue;
        }
        Position position;
        if (declaresItselfGenerated(*text, position)) {
            sink.reportAt("RA6001",
                          file.path,
                          position,
                          "the file declares itself generated and is outside the generated root " +
                              std::string(kGeneratedRoot));
        }
    }

    // RA6002: a vendored dependency without the origin record SPEC-0002 makes
    // the only admission for one. The subjects come from the catalogue, which
    // is where a dependency declares that it is vendored; guessing from
    // directory names would invent a rule rather than mechanize one.
    for (const auto& entry : model.catalog) {
        if (entry.acquisitionClass != "vendored_source") {
            continue;
        }
        if (entry.providerType != "vendor_origin") {
            sink.report("RA6002",
                        entry.id,
                        "the vendored entry names provider type " + entry.providerType +
                            " instead of an origin "
                            "record");
            continue;
        }
        const std::string kRecordPath = entry.providerReference;
        if (kRecordPath.empty() || !model.scan.hasFile(kRecordPath)) {
            sink.report("RA6002", entry.id, "the vendored entry names an origin record that is absent: " + kRecordPath);
            continue;
        }
        auto record = readJsonDocument(model.root / kRecordPath);
        if (!record) {
            sink.report("RA6002", kRecordPath, "the origin record cannot be read: " + record.error().message);
            continue;
        }
        for (const std::string_view kMember : kVendorOriginMembers) {
            if (record->root.find(kMember) != nullptr) {
                continue;
            }
            sink.report("RA6002", kRecordPath, "the origin record is missing the member " + std::string(kMember));
        }
    }

    // RA6003: a maintained authority that resolves beneath a generated or
    // vendored root. Membership is what makes a path maintained, so membership
    // is what is checked, and the walk of the generated root that would
    // otherwise be needed never happens.
    std::vector<std::string> vendoredRoots;
    for (const auto& entry : model.catalog) {
        if (entry.acquisitionClass != "vendored_source" || entry.providerReference.empty()) {
            continue;
        }
        auto record = readJsonDocument(model.root / entry.providerReference);
        if (!record) {
            continue;
        }
        for (const auto& imported : stringArray(record->root, "importedPaths")) {
            vendoredRoots.push_back(imported.ends_with("/") ? imported : imported + "/");
        }
    }

    std::vector<std::string> maintainedPaths;
    for (const auto& array : model.membership) {
        for (const auto& entry : array.entries) {
            maintainedPaths.push_back(entry);
        }
    }
    if (!model.evidenceIndexPath.empty()) {
        maintainedPaths.push_back(model.evidenceIndexPath);
    }
    if (!model.corpusPath.empty()) {
        maintainedPaths.push_back(model.corpusPath);
    }
    for (const auto& path : maintainedPaths) {
        if (path.starts_with(kGeneratedRoot)) {
            sink.report("RA6003", path, "a maintained authority resolves beneath the generated root");
            continue;
        }
        for (const auto& root : vendoredRoots) {
            if (!path.starts_with(root)) {
                continue;
            }
            sink.report("RA6003", path, "a maintained authority resolves beneath the vendored root " + root);
            break;
        }
    }

    // RA6004: a vendor name a public header hands to whoever includes it. The
    // isolation ADR-0005 requires is not about where the header lives but about
    // what it exports, so the subject is the public header and the evidence is
    // its own include list.
    for (const auto& file : model.scan.files) {
        if (!file.path.contains("/include/") || fileExtension(file.path) != ".h") {
            continue;
        }
        auto text = readTextFile(model.root / file.path);
        if (!text) {
            continue;
        }
        for (const auto& include : findIncludes(*text)) {
            if (!include.angled) {
                continue;
            }
            for (const auto& entry : model.catalog) {
                const auto kDot = entry.id.find('.');
                const std::string kToken = kDot == std::string::npos ? entry.id : entry.id.substr(kDot + 1);
                const bool kMatches = include.target == kToken + ".h" || include.target.starts_with(kToken + "/");
                if (!kMatches) {
                    continue;
                }
                sink.reportAt("RA6004",
                              file.path,
                              include.position,
                              "a public header exposes the vendor header " + include.target);
            }
        }
    }
}

} // namespace rawframe::tool::archcheck
