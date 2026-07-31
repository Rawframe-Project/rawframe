#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::verify {

// STD-0007's three verification tiers. Where a unit could belong to two, the
// higher applies, which is why the order here is the order of consequence.
enum class VerificationTier : std::uint8_t {
    Ordinary,
    Authority,
    Hostile,
};

// Written as a chain rather than a switch with a trailing return, because a
// switch over a complete enumeration leaves an arm no input can reach, and an
// unreachable arm is a branch no test can ever close. The last tier is the
// fallthrough, which is also the conservative answer for a value from outside
// this enumeration.
[[nodiscard]] constexpr std::string_view tierName(VerificationTier tier) noexcept {
    if (tier == VerificationTier::Ordinary) {
        return "O";
    }
    if (tier == VerificationTier::Authority) {
        return "A";
    }
    return "H";
}

// The diff branch-coverage floor each tier carries, as a percentage. Every one
// is a `verification_floor` owned by STD-0007, revisable only by amendment with
// evidence. They are stated once, here, so that no lane can hold a different
// number than the standard does.
[[nodiscard]] constexpr int tierBranchFloorPercent(VerificationTier tier) noexcept {
    if (tier == VerificationTier::Ordinary) {
        return 80;
    }
    if (tier == VerificationTier::Authority) {
        return 90;
    }
    return 100;
}

struct TierDeclaration {
    std::string path;
    VerificationTier tier = VerificationTier::Ordinary;
    std::string reason;
    // The declaring authority, so a report can say where a tier came from.
    std::string source;
};

struct TierIndex {
    std::map<std::string, TierDeclaration> units;
    // Units the declarations name that are not on disk, and source units on disk
    // that no declaration names. Both are reported: a stale declaration and a
    // silently untiered unit fail in opposite directions and neither is visible
    // from a coverage percentage.
    std::vector<std::string> declaredButAbsent;
    std::vector<std::string> presentButUndeclared;
};

// Reads the tier declaration of every tool the root repository index lists, and
// of every production module it lists, then checks both directions against the
// tree. Membership is explicit, exactly as SPEC-0001 requires: nothing here
// discovers a tool or a module by walking directories.
[[nodiscard]] Result<TierIndex> readTierIndex(const std::filesystem::path& repositoryRoot);

// The declaration file one root owns, for tests and for the reader above.
[[nodiscard]] Result<std::vector<TierDeclaration>> readTierDeclarationFile(const std::filesystem::path& path,
                                                                           std::string_view declaringRoot);

} // namespace rawframe::tool::verify
