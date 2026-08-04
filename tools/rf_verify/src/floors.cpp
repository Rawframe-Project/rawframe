#include "floors.h"

#include "coverage_exclusions.h"
#include "repository_paths.h"

#include <algorithm>
#include <string>
#include <utility>

namespace rawframe::tool::verify {

namespace {

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

// Integer arithmetic throughout. A percentage computed in floating point and
// then compared against a floor decides a change on the last bit of a division,
// and the same change would land on one host and not on another.
bool meetsFloor(std::int64_t covered, std::int64_t total, int floorPercent) {
    return covered * 100 >= static_cast<std::int64_t>(floorPercent) * total;
}

// Only ever called for a unit that missed its floor, and a unit with no branch
// conditions cannot miss one: `meetsFloor` compares `covered * 100` against
// `floor * 0`, which every non-negative count satisfies. The divisor is
// therefore positive here, and a zero guard would be a branch no input can take.
std::string percentText(std::int64_t covered, std::int64_t total) {
    const std::int64_t kTenths = (covered * 1000) / total;
    return std::to_string(kTenths / 10) + "." + std::to_string(kTenths % 10) + " percent";
}

} // namespace

Result<FloorEvaluation> evaluateFloors(const std::filesystem::path& repositoryRoot,
                                       const ChangedLines& changed,
                                       const CoverageExport& coverage,
                                       const TierIndex& tiers) {
    FloorEvaluation evaluation;

    for (const auto& [path, lines] : changed.files) {
        if (!isMaintainedSourceUnit(path)) {
            ++evaluation.changedNonSourcePaths;
            continue;
        }

        const auto kDeclaration = tiers.units.find(path);
        if (kDeclaration == tiers.units.end()) {
            evaluation.findings.report(kRuleUndeclaredTier,
                                       path,
                                       "a changed source unit carries no declared verification tier, so no floor "
                                       "applies to it and none can");
            continue;
        }

        const auto kCovered = coverage.files.find(path);
        if (kCovered == coverage.files.end()) {
            if (path.ends_with(".cpp")) {
                return reject(FailureCode::UncoveredChangedFile,
                              path,
                              "the coverage export does not describe a changed translation unit, so the lane did not "
                              "build or did not run it");
            }
            // A header the export does not name contributed no instrumented
            // code to any translation unit, which is the ordinary case for a
            // header that declares rather than defines. Coverage has nothing to
            // say about it, and a finding here would be unanswerable: there is
            // no test that can raise the coverage of a declaration. The count
            // is reported so the fact stays visible without becoming a verdict.
            ++evaluation.changedHeadersWithoutInstrumentedCode;
            continue;
        }

        UnitVerdict verdict;
        verdict.path = path;
        verdict.tier = kDeclaration->second.tier;
        verdict.floorPercent = tierBranchFloorPercent(verdict.tier);

        // The unit's own bytes, read once and only when it has changed regions
        // to classify. A unit the export names must be readable: it was compiled
        // during this run, so a source file that is not there now means the
        // export and the tree disagree about what was measured.
        auto unit = SourceUnit::read(repositoryRoot / path);
        if (!unit) {
            return std::unexpected(unit.error());
        }

        for (const auto& region : kCovered->second.branches) {
            if (!lines.contains(region.line)) {
                continue;
            }
            switch (classifyBranchRegion(*unit, region)) {
            case BranchExclusion::ConstantCondition:
                verdict.excludedConstantConditions += 2;
                continue;
            case BranchExclusion::SynthesizedBody:
                verdict.excludedSynthesizedConditions += 2;
                continue;
            case BranchExclusion::None:
                break;
            }
            verdict.changedConditions += 2;
            verdict.coveredConditions += static_cast<std::int64_t>(region.trueCovered());
            verdict.coveredConditions += static_cast<std::int64_t>(region.falseCovered());
            if (!region.trueCovered() || !region.falseCovered()) {
                verdict.uncoveredBranchLines.push_back(region.line);
            }
        }
        std::ranges::sort(verdict.uncoveredBranchLines);
        const auto kRemoved = std::ranges::unique(verdict.uncoveredBranchLines);
        verdict.uncoveredBranchLines.erase(kRemoved.begin(), kRemoved.end());

        verdict.meetsFloor = meetsFloor(verdict.coveredConditions, verdict.changedConditions, verdict.floorPercent);
        if (!verdict.meetsFloor) {
            evaluation.findings.report(kRuleBelowFloor,
                                       path,
                                       "tier " + std::string(tierName(verdict.tier)) + " changed lines measured " +
                                           percentText(verdict.coveredConditions, verdict.changedConditions) +
                                           " branch coverage against a floor of " +
                                           std::to_string(verdict.floorPercent) + " percent");
        }

        // The MC/DC obligation applies to the validating path of a trust
        // boundary, which is what Tier H names. Applying it to every tier would
        // turn the narrowest rule in the standard into the broadest one.
        if (verdict.tier == VerificationTier::Hostile) {
            for (const auto& decision : kCovered->second.decisions) {
                if (!lines.contains(decision.line)) {
                    continue;
                }
                ++verdict.changedDecisions;
                if (decisionIsIndependentlyCovered(decision)) {
                    continue;
                }
                ++verdict.uncoveredDecisions;
                evaluation.findings.report(kRuleMcdcUncovered,
                                           path,
                                           "the decision at line " + std::to_string(decision.line) +
                                               " has a condition with no independence pair, so it is not covered to "
                                               "MC/DC");
            }
        }

        evaluation.units.push_back(std::move(verdict));
    }

    for (const auto& stale : tiers.declaredButAbsent) {
        evaluation.findings.report(
            kRuleStaleTier, stale, "a verification tier is declared for a unit that is not there");
    }
    for (const auto& undeclared : tiers.presentButUndeclared) {
        evaluation.findings.report(
            kRuleUndeclaredTier, undeclared, "a maintained source unit carries no declared verification tier");
    }

    return evaluation;
}

} // namespace rawframe::tool::verify
