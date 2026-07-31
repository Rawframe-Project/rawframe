#pragma once

#include "failure.h"
#include "json_reader.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

struct Rule {
    std::string id;
    std::string authority;
    std::string title;
    std::string subjectKind;
    std::string severity;
    std::string landsWith;
};

struct PolicyHistoryEntry {
    std::int64_t policyVersion = 0;
    std::string ruleSetSeal;
};

struct RuleCorpus {
    std::int64_t policyVersion = 0;
    std::string ruleSetSeal;
    std::vector<PolicyHistoryEntry> policyHistory;
    std::vector<Rule> rules;

    [[nodiscard]] const Rule* find(std::string_view id) const noexcept;
};

// The integrity seal of a rule set. It is deliberately not a cryptographic
// digest: SPEC-0044 gives this tool no digest provider because it verifies
// nothing cryptographic. The seal exists so that a change to the rules that
// does not increase the policy version is mechanically visible, which is the
// one thing RA1006 has to be able to see.
[[nodiscard]] std::string sealRules(const std::vector<Rule>& rules);

// Loads and validates the corpus grammar. Every defect here is a failure of the
// tool's own input rather than a finding about the repository: a corpus the tool
// cannot trust cannot be used to judge anything, so it must not be able to
// produce a clean result.
[[nodiscard]] Result<RuleCorpus> loadRuleCorpus(const std::filesystem::path& corpusPath);

[[nodiscard]] Result<RuleCorpus> parseRuleCorpus(const JsonNode& root);

} // namespace rawframe::tool::archcheck
