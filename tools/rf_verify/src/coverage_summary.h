#pragma once

#include "coverage_export.h"
#include "failure.h"
#include "tier_declarations.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rawframe::tool::verify {

// The uncovered set of one file. STD-0007 makes this the review artifact and
// the percentage the derived view, so the set is what this carries and the
// percentage is computed from it rather than the other way around.
struct FileCoverageSummary {
    std::string path;
    std::string tier;
    CoverageSummary counts;
    std::vector<std::uint32_t> uncoveredLines;
    std::vector<std::uint32_t> partiallyCoveredBranchLines;
    std::vector<std::uint32_t> uncoveredDecisionLines;
};

struct TreeCoverageSummary {
    CoverageSummary totals;
    std::vector<FileCoverageSummary> files;
    // Lines the report did not list because the set exceeded its ceiling. A
    // truncated set that did not say so would read as a shorter uncovered set,
    // which is the one direction this artifact must never fail in.
    std::size_t omittedUncoveredLines = 0;
    std::size_t droppedForeignFiles = 0;
};

// Whole-tree coverage is a `verification_objective` under STD-0007: measured,
// published with every run, and never gated. Nothing here returns a verdict.
[[nodiscard]] Result<TreeCoverageSummary> summarizeCoverage(const CoverageExport& coverage, const TierIndex& tiers);

} // namespace rawframe::tool::verify
