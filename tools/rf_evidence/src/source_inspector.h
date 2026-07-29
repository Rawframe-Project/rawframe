#pragma once

#include "failure.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

// STD-0001 file thresholds, measured in physical lines. The hard failure gate
// is a typed Failure rather than a gate value, because the standard makes it a
// verification failure instead of a report classification.
inline constexpr std::size_t kOwnershipReviewLines = 600;
inline constexpr std::size_t kFeatureGrowthStopLines = 1'000;
inline constexpr std::size_t kHardFailureLines = 1'500;

// STD-0001 requires warning output at 600 physical lines and blocking output at
// 1,000. The standard permits a file to remain at or above 1,000 when its single
// responsibility is documented with a bounded containment plan, so this classifies
// output severity and does not by itself fail verification.
enum class SourceGate : std::uint8_t {
    Ok,
    OwnershipReviewRequired,
    FeatureGrowthStopped,
};

[[nodiscard]] constexpr SourceGate sourceGateForLines(std::size_t lines) noexcept {
    if (lines >= kFeatureGrowthStopLines) {
        return SourceGate::FeatureGrowthStopped;
    }
    if (lines >= kOwnershipReviewLines) {
        return SourceGate::OwnershipReviewRequired;
    }
    return SourceGate::Ok;
}

[[nodiscard]] constexpr std::string_view sourceGateName(SourceGate gate) noexcept {
    switch (gate) {
    case SourceGate::OwnershipReviewRequired:
        return "ownership_review_required";
    case SourceGate::FeatureGrowthStopped:
        return "feature_growth_stopped";
    case SourceGate::Ok:
        break;
    }
    return "ok";
}

[[nodiscard]] constexpr std::string_view sourceGateSeverity(SourceGate gate) noexcept {
    switch (gate) {
    case SourceGate::OwnershipReviewRequired:
        return "warning";
    case SourceGate::FeatureGrowthStopped:
        return "blocking";
    case SourceGate::Ok:
        break;
    }
    return "ok";
}

// The 1,500-line gate is a verification failure rather than a report
// classification. It is exposed as its own rule so that it can be rejected
// directly, without a fixture file that would itself become maintained source
// and trip the gate during ordinary runs.
[[nodiscard]] Status admitPhysicalLineCount(std::string_view path, std::size_t lines);

// STD-0001 exempts generated output and vendored third-party source from the
// numerical thresholds, but only while they are mechanically identifiable and
// segregated from maintained source. This repository declares both by location,
// which is what the standard asks for: ADR-0022 places generated material
// beneath `out/` and vendored material beneath `third_party/`. Classification
// therefore reads a path and never a file's size, name, or content.
//
// Today no tool root contains either, so every reported file is maintained.
// That is the property worth measuring rather than assuming, because the day a
// generated header lands inside a tool root, the difference between a warning
// and a false hard failure is exactly this classification.
enum class SourceClassification : std::uint8_t {
    Maintained,
    Generated,
    Vendored,
};

[[nodiscard]] constexpr std::string_view sourceClassificationName(SourceClassification classification) noexcept {
    switch (classification) {
    case SourceClassification::Generated:
        return "generated";
    case SourceClassification::Vendored:
        return "vendored";
    case SourceClassification::Maintained:
        break;
    }
    return "maintained";
}

[[nodiscard]] constexpr bool isExemptFromLineThresholds(SourceClassification classification) noexcept {
    return classification != SourceClassification::Maintained;
}

// Takes a repository-relative path with forward slashes, as the reports use.
[[nodiscard]] SourceClassification classifyRepositoryPath(std::string_view relativePath) noexcept;

struct SourceOwnershipEntry {
    std::string path;
    std::size_t lines;
    std::string owner;
    SourceGate gate;
    SourceClassification classification{SourceClassification::Maintained};
};

[[nodiscard]] Result<std::vector<SourceOwnershipEntry>>
inspectSourceOwnership(const std::filesystem::path& repositoryRoot);

} // namespace rawframe::tool::evidence
