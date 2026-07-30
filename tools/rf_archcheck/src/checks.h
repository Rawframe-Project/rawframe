#pragma once

#include "findings.h"
#include "repository_model.h"
#include "rule_corpus.h"

namespace rawframe::tool::archcheck {

// The seven ADR-0077 check classes. Each function owns exactly the rules of its
// class, so a rule has one implementation and a class has one file, and neither
// can quietly acquire a subject belonging to the other.
void checkManifestAndIndex(const RepositoryModel& model, const RuleCorpus& corpus, FindingSink& sink);
void checkMembershipReality(const RepositoryModel& model, FindingSink& sink);
void checkDependencyEdges(const RepositoryModel& model, FindingSink& sink);
void checkNegativeClosures(const RepositoryModel& model, FindingSink& sink);
void checkSourceHygiene(const RepositoryModel& model, FindingSink& sink);
void checkGeneratedAndVendoredSeparation(const RepositoryModel& model, FindingSink& sink);
void checkManifestProjections(const RepositoryModel& model, FindingSink& sink);

// The number of subjects each rule had to look at, so that `list_rules` can say
// the difference between a rule that passed and a rule that had nothing to look
// at. SPEC-0044 requires that difference to be visible.
struct SubjectCount {
    std::string ruleId;
    std::size_t subjects = 0;
};

[[nodiscard]] std::vector<SubjectCount> countSubjects(const RepositoryModel& model, const RuleCorpus& corpus);

} // namespace rawframe::tool::archcheck
