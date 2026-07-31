#pragma once

#include "checks.h"
#include "failure.h"
#include "findings.h"
#include "rule_corpus.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::archcheck {

struct CheckOutcome {
    std::int64_t policyVersion = 0;
    std::vector<Finding> findings;
    std::vector<SubjectCount> subjectCounts;
};

// Runs every rule in the corpus over one repository. The corpus is loaded first
// and a corpus defect is a failure rather than a finding, because a tool that
// cannot trust its own rules must not be able to report a clean repository.
[[nodiscard]] Result<CheckOutcome> checkRepository(const std::filesystem::path& root,
                                                   const std::filesystem::path& corpusPath,
                                                   const std::string& corpusRelativePath);

} // namespace rawframe::tool::archcheck
