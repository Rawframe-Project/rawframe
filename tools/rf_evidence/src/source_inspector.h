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

struct SourceOwnershipEntry {
    std::string path;
    std::size_t lines;
    std::string owner;
    SourceGate gate;
};

[[nodiscard]] Result<std::vector<SourceOwnershipEntry>>
inspectSourceOwnership(const std::filesystem::path& repositoryRoot);

} // namespace rawframe::tool::evidence
