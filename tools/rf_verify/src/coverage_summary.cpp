#include "coverage_summary.h"

#include "tool_limits.h"

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>

namespace rawframe::tool::verify {

namespace {

void accumulate(CoverageCounts& total, const CoverageCounts& part) {
    total.count += part.count;
    total.covered += part.covered;
}

} // namespace

Result<TreeCoverageSummary> summarizeCoverage(const CoverageExport& coverage, const TierIndex& tiers) {
    TreeCoverageSummary summary;
    summary.droppedForeignFiles = coverage.droppedForeignFiles;

    std::size_t listedUncoveredLines = 0;
    for (const auto& [path, file] : coverage.files) {
        FileCoverageSummary entry;
        entry.path = path;
        if (const auto kDeclaration = tiers.units.find(path); kDeclaration != tiers.units.end()) {
            entry.tier = std::string(tierName(kDeclaration->second.tier));
        }
        entry.counts = file.summary;

        for (const auto& [line, count] : file.lineCounts) {
            if (count != 0) {
                continue;
            }
            if (listedUncoveredLines >= kMaximumReportedUncoveredLines) {
                ++summary.omittedUncoveredLines;
                continue;
            }
            entry.uncoveredLines.push_back(line);
            ++listedUncoveredLines;
        }

        for (const auto& region : file.branches) {
            if (region.trueCovered() && region.falseCovered()) {
                continue;
            }
            entry.partiallyCoveredBranchLines.push_back(region.line);
        }
        std::ranges::sort(entry.partiallyCoveredBranchLines);
        const auto kRemovedBranches = std::ranges::unique(entry.partiallyCoveredBranchLines);
        entry.partiallyCoveredBranchLines.erase(kRemovedBranches.begin(), kRemovedBranches.end());

        for (const auto& decision : file.decisions) {
            if (decisionIsIndependentlyCovered(decision)) {
                continue;
            }
            entry.uncoveredDecisionLines.push_back(decision.line);
        }
        std::ranges::sort(entry.uncoveredDecisionLines);
        const auto kRemovedDecisions = std::ranges::unique(entry.uncoveredDecisionLines);
        entry.uncoveredDecisionLines.erase(kRemovedDecisions.begin(), kRemovedDecisions.end());

        accumulate(summary.totals.lines, entry.counts.lines);
        accumulate(summary.totals.branches, entry.counts.branches);
        accumulate(summary.totals.regions, entry.counts.regions);
        accumulate(summary.totals.mcdc, entry.counts.mcdc);
        summary.files.push_back(std::move(entry));
    }

    return summary;
}

} // namespace rawframe::tool::verify
