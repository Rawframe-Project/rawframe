#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::verify {

// A Finding is a statement about the change under measurement, and every one
// cites the accepted authority that makes it a finding. The tool introduces no
// rule of its own: each identifier below is a sentence STD-0007 already wrote.
struct Finding {
    std::string ruleId;
    std::string path;
    std::string message;
};

struct FindingSet {
    std::vector<Finding> findings;

    void report(std::string_view ruleId, std::string_view path, std::string message) {
        findings.push_back(Finding{std::string(ruleId), std::string(path), std::move(message)});
    }

    [[nodiscard]] bool empty() const noexcept {
        return findings.empty();
    }
};

// STD-0007, "Coverage criteria and floors": a change below its tier's diff
// branch-coverage floor does not land.
inline constexpr std::string_view kRuleBelowFloor = "RV1001";
// STD-0007, Tier H: every decision in the validating path covered to MC/DC.
inline constexpr std::string_view kRuleMcdcUncovered = "RV1002";
// STD-0007, acceptance criteria: every source unit in a landed module carries a
// declared verification tier.
inline constexpr std::string_view kRuleUndeclaredTier = "RV1003";
// The same rule read in the other direction: a declaration naming a unit that is
// not there is a tier nobody can act on.
inline constexpr std::string_view kRuleStaleTier = "RV1004";
// STD-0007, requirement-to-test binding: a test that binds a criterion no
// accepted document declares. The report exists to make drift visible, and
// drift in this direction is the kind a generated report can actually see.
inline constexpr std::string_view kRuleUndeclaredCriterion = "RV2001";

} // namespace rawframe::tool::verify
