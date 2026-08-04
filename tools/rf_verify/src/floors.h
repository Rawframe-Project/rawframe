#pragma once

#include "coverage_export.h"
#include "diff_reader.h"
#include "failure.h"
#include "findings.h"
#include "tier_declarations.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::verify {

// What one changed source unit measured, stated in the terms STD-0007 uses. The
// counts are branch conditions rather than branch regions, because a region
// carries two outcomes and a floor that counted regions would call a decision
// covered when only one of its two ways through had ever run.
struct UnitVerdict {
    std::string path;
    VerificationTier tier = VerificationTier::Ordinary;
    std::int64_t changedConditions = 0;
    std::int64_t coveredConditions = 0;
    int floorPercent = 0;
    bool meetsFloor = true;
    std::vector<std::uint32_t> uncoveredBranchLines;
    std::size_t changedDecisions = 0;
    std::size_t uncoveredDecisions = 0;
    // Branch outcomes STD-0007 removes from the denominator, counted by reason
    // so the report says which and how many rather than quietly measuring a
    // smaller unit. A unit that excludes most of its outcomes is telling a
    // reader that coverage is not what verifies it.
    std::size_t excludedConstantConditions = 0;
    std::size_t excludedSynthesizedConditions = 0;
};

struct FloorEvaluation {
    std::vector<UnitVerdict> units;
    FindingSet findings;
    // Changed paths that are not maintained first-party source units: a
    // manifest, a preset, a document. They are counted rather than dropped, so a
    // change that touched nothing measurable says so instead of reporting a
    // clean verdict over an empty set.
    std::size_t changedNonSourcePaths = 0;
    // Changed headers the export does not name. A header that declares rather
    // than defines contributes no instrumented code, so coverage cannot speak
    // about it either way; the count keeps that visible without inventing a
    // finding no test could answer.
    std::size_t changedHeadersWithoutInstrumentedCode = 0;
};

// Evaluates the diff-scoped floors. A changed translation unit the export does
// not describe is a typed failure and not a finding: it means the lane did not
// build or did not run that unit, so nothing can be concluded about the change.
//
// The repository root is read: STD-0007's excluded outcomes are decided from the
// source bytes of the unit being measured, which is what keeps the exclusion
// mechanical rather than declared.
[[nodiscard]] Result<FloorEvaluation> evaluateFloors(const std::filesystem::path& repositoryRoot,
                                                     const ChangedLines& changed,
                                                     const CoverageExport& coverage,
                                                     const TierIndex& tiers);

} // namespace rawframe::tool::verify
