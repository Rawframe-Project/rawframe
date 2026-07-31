#include "engine.h"

#include "repository_model.h"
#include "repository_scan.h"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace rawframe::tool::archcheck {

namespace {

std::size_t countManifests(const RepositoryModel& model) {
    return static_cast<std::size_t>(std::ranges::count_if(model.manifests, [](const LoadedManifest& manifest) {
        return manifest.present;
    }));
}

std::size_t countMatching(const RepositoryModel& model, bool (*predicate)(std::string_view)) {
    return static_cast<std::size_t>(std::ranges::count_if(model.scan.files, [predicate](const ScannedFile& file) {
        return predicate(file.path);
    }));
}

bool isModuleManifest(std::string_view path) {
    return path.ends_with("/module.json");
}

bool isToolManifest(std::string_view path) {
    return path.ends_with("/tool.json");
}

bool isPublicHeader(std::string_view path) {
    return path.contains("/include/") && path.ends_with(".h");
}

bool isMaintainedSource(std::string_view path) {
    if (path.starts_with("source/")) {
        return !path.contains("/tests/");
    }
    return path.starts_with("tools/") && path.contains("/src/");
}

std::size_t membershipEntries(const RepositoryModel& model, std::string_view name) {
    const MembershipArray* array = model.membershipArray(name);
    return array == nullptr ? 0 : array->entries.size();
}

} // namespace

std::vector<SubjectCount> countSubjects(const RepositoryModel& model, const RuleCorpus& corpus) {
    // A rule that found nothing and a rule that had nothing to look at produce
    // the same silence. This is what tells them apart, and it is why every rule
    // has to answer here even when its subjects do not exist yet.
    const std::size_t kManifests = countManifests(model);
    const std::size_t kModules = countMatching(model, isModuleManifest);
    const std::size_t kTools = countMatching(model, isToolManifest);
    const std::size_t kBuildFiles = model.buildLane.size();
    const std::size_t kSources = countMatching(model, isMaintainedSource);
    const std::size_t kPublicHeaders = countMatching(model, isPublicHeader);
    const std::size_t kTargets = membershipEntries(model, "targets");
    const std::size_t kVendored =
        static_cast<std::size_t>(std::ranges::count_if(model.catalog, [](const CatalogEntry& entry) {
            return entry.acquisitionClass == "vendored_source";
        }));

    // Each rule names the population it walks. A table rather than a chain of
    // comparisons, because several rules share a population and a chain that
    // repeats the same assignment reads as though the cases differed.
    const std::vector<std::pair<std::string_view, std::size_t>> kPopulations{
        {"RA1002", kManifests},
        {"RA1003", model.membership.size()},
        {"RA1004", membershipEntries(model, "tools")},
        {"RA1005", kManifests},
        {"RA1006", 1},
        {"RA2001", membershipEntries(model, "modules")},
        {"RA2002", kModules},
        {"RA2003", kBuildFiles},
        {"RA2004", kModules},
        {"RA2005", kModules},
        {"RA2006", kTools},
        {"RA3001", kSources},
        {"RA3002", kSources},
        {"RA3003", kModules},
        {"RA3004", kModules},
        {"RA3005", kBuildFiles},
        {"RA4001", kTargets},
        {"RA4002", kBuildFiles},
        {"RA4004", kTargets},
        {"RA5001", kBuildFiles},
        {"RA5002", kSources},
        {"RA5003", kBuildFiles},
        {"RA5004", kSources},
        {"RA5005", model.scan.files.size()},
        {"RA6001", kSources},
        {"RA6002", kVendored},
        {"RA6003", kManifests},
        {"RA6004", kPublicHeaders},
        {"RA7001", kTargets},
        {"RA7002", kModules},
    };

    std::vector<SubjectCount> counts;
    for (const auto& rule : corpus.rules) {
        const auto kPopulation = std::ranges::find_if(kPopulations, [&rule](const auto& entry) {
            return entry.first == rule.id;
        });
        counts.push_back(SubjectCount{rule.id, kPopulation == kPopulations.end() ? 0 : kPopulation->second});
    }
    return counts;
}

Result<CheckOutcome> checkRepository(const std::filesystem::path& root,
                                     const std::filesystem::path& corpusPath,
                                     const std::string& corpusRelativePath) {
    auto corpus = loadRuleCorpus(corpusPath);
    if (!corpus) {
        return std::unexpected(corpus.error());
    }
    auto model = loadRepositoryModel(root, corpusRelativePath);
    if (!model) {
        return std::unexpected(model.error());
    }

    FindingSink sink(*corpus);
    checkManifestAndIndex(*model, *corpus, sink);
    checkMembershipReality(*model, sink);
    checkDependencyEdges(*model, sink);
    checkNegativeClosures(*model, sink);
    checkSourceHygiene(*model, sink);
    checkGeneratedAndVendoredSeparation(*model, sink);
    checkManifestProjections(*model, sink);

    if (sink.sawUnknownRule()) {
        return std::unexpected(Failure{FailureCode::InvalidCorpus,
                                       corpusRelativePath,
                                       "a check reported against a rule the corpus does not carry"});
    }
    if (sink.overflowed()) {
        return std::unexpected(Failure{FailureCode::LimitExceeded,
                                       root.generic_string(),
                                       "the repository produced more findings than the ceiling admits"});
    }

    CheckOutcome outcome;
    outcome.policyVersion = corpus->policyVersion;
    outcome.findings = sink.findings();
    sortFindings(outcome.findings);
    outcome.subjectCounts = countSubjects(*model, *corpus);
    return outcome;
}

} // namespace rawframe::tool::archcheck
