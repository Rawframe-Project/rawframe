#pragma once

#include "failure.h"
#include "rule_corpus.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

inline constexpr std::string_view kToolVersion = "1.0.0";

struct Position {
    std::size_t line = 0;
    std::size_t column = 0;

    [[nodiscard]] bool present() const noexcept {
        return line != 0 && column != 0;
    }
};

struct Finding {
    std::string ruleId;
    std::string authority;
    std::string subject;
    Position position;
    std::string detail;
};

// The one place a finding is created. It copies the authority from the rule so
// that a reader never has to hold the corpus to know which document was
// violated, and it refuses an identity the corpus does not carry, which keeps a
// check from inventing a rule at the point of use.
class FindingSink {
public:
    explicit FindingSink(const RuleCorpus& corpus) noexcept : corpus_(&corpus) {
    }

    void report(std::string_view ruleId, std::string subject, std::string detail);
    void reportAt(std::string_view ruleId, std::string subject, Position position, std::string detail);

    [[nodiscard]] const std::vector<Finding>& findings() const noexcept {
        return findings_;
    }
    [[nodiscard]] bool overflowed() const noexcept {
        return overflowed_;
    }
    [[nodiscard]] bool sawUnknownRule() const noexcept {
        return unknownRule_;
    }

private:
    const RuleCorpus* corpus_;
    std::vector<Finding> findings_;
    bool overflowed_ = false;
    bool unknownRule_ = false;
};

// A total order with no ties: rule, then subject, then position, then detail.
// Detail is the last tiebreak rather than a comparison anyone should need,
// because two findings of one rule on one line of one file must still have a
// defined order or the output stops being byte-identical.
[[nodiscard]] bool findingPrecedes(const Finding& left, const Finding& right) noexcept;

void sortFindings(std::vector<Finding>& findings);

// The findings document in the SPEC-0001 maintained form, with the single final
// newline included.
[[nodiscard]] std::string renderFindingsDocument(std::int64_t policyVersion, const std::vector<Finding>& findings);

} // namespace rawframe::tool::archcheck
