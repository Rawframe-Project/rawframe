#include "checks.h"
#include "text_scan.h"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>

namespace rawframe::tool::archcheck {

namespace {

// A membership entry has to be one explicit manifest path. A wildcard, a bare
// directory, or a duplicate all mean the same thing: the array stopped being the
// authority and became a hint that something else resolves.
bool looksLikeManifestPath(std::string_view entry) {
    return entry.ends_with(".json") && !entry.contains('*') && !entry.contains('?') && !entry.contains("..");
}

struct SuspectString {
    std::string_view needle;
    std::string_view reason;
};

constexpr std::array kSuspectSubstrings{
    SuspectString{"http://", "a URL"},
    SuspectString{"https://", "a URL"},
    SuspectString{"git://", "a URL"},
    SuspectString{"ssh://", "a URL"},
    SuspectString{"file://", "a URL"},
};

constexpr std::array kFloatingTags{
    std::string_view{"latest"},
    std::string_view{"HEAD"},
    std::string_view{"master"},
    std::string_view{"main"},
    std::string_view{"nightly"},
    std::string_view{"trunk"},
};

constexpr std::array kCredentialKeys{
    std::string_view{"password"},
    std::string_view{"secret"},
    std::string_view{"token"},
    std::string_view{"apiKey"},
    std::string_view{"credential"},
};

bool looksLikeVersionRange(std::string_view value) {
    if (value.empty()) {
        return false;
    }
    // A range is a comparison or a wildcard applied to something that otherwise
    // looks like a version. A bare `1.2.3` is exact and admitted.
    for (const std::string_view kMarker : {std::string_view{">="},
                                           std::string_view{"<="},
                                           std::string_view{"^"},
                                           std::string_view{"~"},
                                           std::string_view{".x"},
                                           std::string_view{".*"}}) {
        if (!value.contains(kMarker)) {
            continue;
        }
        const bool kHasDigit = std::ranges::any_of(value, [](char character) {
            return character >= '0' && character <= '9';
        });
        if (kHasDigit) {
            return true;
        }
    }
    return false;
}

// A member named for a credential that declares the tool holds none is the
// opposite of the defect. RA1005 is about a manifest carrying a credential, so
// the value decides, and the denials a manifest is allowed to write are named
// rather than guessed.
constexpr std::array kCredentialDenials{
    std::string_view{"none"},
    std::string_view{"denied"},
    std::string_view{"forbidden"},
    std::string_view{"no"},
    std::string_view{"false"},
    std::string_view{"unused"},
    std::string_view{"prohibited"},
};

bool carriesCredential(const JsonNode& value) {
    if (value.kind == JsonKind::Boolean) {
        return value.boolean;
    }
    if (value.kind != JsonKind::String || value.text.empty()) {
        return false;
    }
    return std::ranges::none_of(kCredentialDenials, [&value](std::string_view denial) {
        return denial == value.text;
    });
}

bool looksLikeLocalPath(std::string_view value) {
    if (value.starts_with("/") || value.starts_with("\\\\")) {
        return true;
    }
    if (value.size() >= 3 && value.at(1) == ':' && (value.at(2) == '/' || value.at(2) == '\\')) {
        return true;
    }
    return value.starts_with("~/");
}

void inspectStrings(const JsonNode& node,
                    const std::string& manifestPath,
                    const std::string& keyPath,
                    FindingSink& sink) {
    switch (node.kind) {
    case JsonKind::String: {
        // `$schema` is the one path a manifest is required to carry, and it is
        // relative by construction, so it is exempt from the local-path rule
        // rather than from every rule.
        const bool kIsSchema = keyPath == "$schema";
        for (const auto& suspect : kSuspectSubstrings) {
            if (node.text.contains(suspect.needle)) {
                sink.report("RA1005",
                            manifestPath,
                            "member " + keyPath + " carries " + std::string(suspect.reason) + ": " + node.text);
                return;
            }
        }
        if (!kIsSchema && looksLikeLocalPath(node.text)) {
            sink.report("RA1005", manifestPath, "member " + keyPath + " carries a local path: " + node.text);
            return;
        }
        if (looksLikeVersionRange(node.text)) {
            sink.report("RA1005", manifestPath, "member " + keyPath + " carries a version range: " + node.text);
            return;
        }
        for (const std::string_view kTag : kFloatingTags) {
            if (node.text != kTag) {
                continue;
            }
            sink.report("RA1005", manifestPath, "member " + keyPath + " carries a floating tag: " + node.text);
            return;
        }
        return;
    }
    case JsonKind::Array:
        for (std::size_t index = 0; index < node.elements.size(); ++index) {
            inspectStrings(node.elements.at(index), manifestPath, keyPath + "[" + std::to_string(index) + "]", sink);
        }
        return;
    case JsonKind::Object:
        for (const auto& member : node.members) {
            for (const std::string_view kKey : kCredentialKeys) {
                if (!member.first.contains(kKey) || !carriesCredential(member.second)) {
                    continue;
                }
                sink.report(
                    "RA1005", manifestPath, "member " + keyPath + "." + member.first + " carries a credential value");
                break;
            }
            inspectStrings(
                member.second, manifestPath, keyPath.empty() ? member.first : keyPath + "." + member.first, sink);
        }
        return;
    case JsonKind::Null:
    case JsonKind::Boolean:
    case JsonKind::Number:
        return;
    }
}

} // namespace

void checkManifestAndIndex(const RepositoryModel& model, const RuleCorpus& corpus, FindingSink& sink) {
    // RA1002: every maintained manifest is stored in the form SPEC-0001 fixes.
    for (const auto& manifest : model.manifests) {
        if (!manifest.present) {
            continue;
        }
        std::string expected = serializeMaintainedForm(manifest.document.root);
        expected.push_back('\n');
        if (expected == manifest.document.bytes) {
            continue;
        }
        std::size_t line = 1;
        std::size_t column = 1;
        const std::size_t kShortest = std::min(expected.size(), manifest.document.bytes.size());
        std::size_t index = 0;
        while (index < kShortest && expected.at(index) == manifest.document.bytes.at(index)) {
            if (manifest.document.bytes.at(index) == '\n') {
                ++line;
                column = 1;
            } else {
                ++column;
            }
            ++index;
        }
        sink.reportAt("RA1002",
                      manifest.path,
                      Position{line, column},
                      "the stored bytes and the maintained form first differ at byte " + std::to_string(index));
    }

    // RA1003: every membership array other than the tools array is the explicit
    // authority for its kind. The tools array has its own rule, because a tool
    // has obligations a platform manifest does not.
    for (const auto& array : model.membership) {
        if (array.name == "tools") {
            continue;
        }
        for (std::size_t index = 0; index < array.entries.size(); ++index) {
            const std::string& kEntry = array.entries.at(index);
            if (!looksLikeManifestPath(kEntry)) {
                sink.report("RA1003",
                            "repository.json",
                            "membership array " + array.name +
                                " carries an entry that is not one explicit manifest "
                                "path: " +
                                kEntry);
                continue;
            }
            if (std::ranges::count(array.entries, kEntry) > 1) {
                sink.report("RA1003",
                            "repository.json",
                            "membership array " + array.name + " lists the same manifest twice: " + kEntry);
                continue;
            }
            if (!model.scan.hasFile(kEntry)) {
                sink.report("RA1003",
                            "repository.json",
                            "membership array " + array.name + " lists a manifest that is absent: " + kEntry);
            }
        }
    }

    // RA1004: exactly one manifest per tool, present, and listed once.
    if (const MembershipArray* tools = model.membershipArray("tools"); tools != nullptr) {
        for (const auto& entry : tools->entries) {
            if (std::ranges::count(tools->entries, entry) > 1) {
                sink.report("RA1004", "repository.json", "the tools array lists the same manifest twice: " + entry);
                continue;
            }
            if (!looksLikeManifestPath(entry) || !entry.ends_with("/tool.json")) {
                sink.report("RA1004",
                            "repository.json",
                            "the tools array carries an entry that is not one tool manifest path: " + entry);
                continue;
            }
            if (!model.scan.hasFile(entry)) {
                sink.report("RA1004", "repository.json", "the tools array lists a manifest that is absent: " + entry);
            }
        }
        for (const auto& tool : model.tools) {
            const auto kSameId = std::ranges::count_if(model.tools, [&tool](const ToolManifest& other) {
                return other.id == tool.id;
            });
            if (kSameId > 1) {
                sink.report(
                    "RA1004", tool.manifestPath, "the tool identity is claimed by more than one manifest: " + tool.id);
            }
            const std::string kExpected = tool.root + "/tool.json";
            if (kExpected != tool.manifestPath) {
                sink.report("RA1004",
                            tool.manifestPath,
                            "the tool manifest is not the one manifest of its root: expected " + kExpected);
            }
        }
    }

    // RA1005: no manifest carries an identity that belongs to a lock, a
    // registry, or a workstation.
    for (const auto& manifest : model.manifests) {
        if (!manifest.present) {
            continue;
        }
        inspectStrings(manifest.document.root, manifest.path, {}, sink);
    }

    // RA1006: the corpus seal agrees with the rules, and the current policy
    // version is the one the history ends with.
    const std::string kSeal = sealRules(corpus.rules);
    if (kSeal != corpus.ruleSetSeal) {
        sink.report("RA1006",
                    model.corpusPath,
                    "the rules changed without the seal following them: the rules seal to " + kSeal +
                        " and the corpus "
                        "records " +
                        corpus.ruleSetSeal);
    }
    if (corpus.policyHistory.empty()) {
        return;
    }
    const auto& kCurrent = corpus.policyHistory.back();
    if (kCurrent.policyVersion != corpus.policyVersion) {
        sink.report("RA1006",
                    model.corpusPath,
                    "the policy history ends at version " + std::to_string(kCurrent.policyVersion) +
                        " and the corpus declares version " + std::to_string(corpus.policyVersion));
    }
    if (kCurrent.ruleSetSeal != corpus.ruleSetSeal) {
        sink.report("RA1006",
                    model.corpusPath,
                    "the policy history records seal " + kCurrent.ruleSetSeal +
                        " for the current version and the "
                        "corpus records " +
                        corpus.ruleSetSeal);
    }
    for (std::size_t index = 0; index + 1 < corpus.policyHistory.size(); ++index) {
        if (corpus.policyHistory.at(index).ruleSetSeal != corpus.ruleSetSeal) {
            continue;
        }
        sink.report("RA1006",
                    model.corpusPath,
                    "the current rules already sealed to " + corpus.ruleSetSeal + " at policy version " +
                        std::to_string(corpus.policyHistory.at(index).policyVersion));
    }
}

} // namespace rawframe::tool::archcheck
