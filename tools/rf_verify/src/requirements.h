#pragma once

#include "failure.h"
#include "findings.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rawframe::tool::verify {

// How an accepted acceptance criterion is discharged. A criterion no automated
// test can reach is not thereby exempt: it names what discharges it, so the gap
// stays explicit instead of becoming invisible.
//
// `Lane` exists because a criterion can be discharged by something that runs and
// still cannot record a binding. A compile probe, a link probe, a
// compile-must-fail fixture, and the analysis lane itself all either have no
// GoogleTest process to record a property from or are not a test process at all.
// Calling those manual would be false, because nobody performs a procedure, and
// leaving them out of the inventory would leave it short of the corpus it exists
// to account for.
enum class DischargeKind : std::uint8_t {
    Automated,
    Manual,
    Lane,
};

struct DeclaredCriterion {
    // `<DOC-ID>:<criterion>`, the exact value a test records.
    std::string id;
    std::string text;
    DischargeKind discharge = DischargeKind::Automated;
    std::string procedure;
    // What discharges a `Lane` criterion, in words, for the reader of a report.
    std::string dischargedBy;
    // The exact CTest case names a `Lane` criterion is discharged by, when it is
    // discharged by cases rather than by a build target or a lane step. Checked
    // against what the lane actually registers, so the name cannot rot.
    std::vector<std::string> ctestCases;
};

struct CriterionBinding {
    std::string criterionId;
    std::vector<std::string> tests;
};

struct RequirementsReport {
    std::vector<CriterionBinding> bound;
    // Declared, expected to be discharged by a test, and no test records it.
    // STD-0007 makes these visible and counted rather than absent.
    std::vector<DeclaredCriterion> unbound;
    std::vector<DeclaredCriterion> manual;
    std::vector<DeclaredCriterion> lane;
    // Recorded by a test and declared nowhere. This is the drift a generated
    // report can actually see, which is why it is a finding and the unbound set
    // is not.
    std::vector<CriterionBinding> undeclared;
    std::size_t testsRead = 0;
    std::size_t bindingsRead = 0;
    FindingSet findings;
};

// The maintained inventory of accepted acceptance criteria. It carries no test
// links: the links are generated from the run, and an inventory that carried
// them would be the traceability matrix STD-0007 forbids.
[[nodiscard]] Result<std::vector<DeclaredCriterion>> readCriteriaInventory(const std::filesystem::path& path);

// Reads GoogleTest's own machine-readable report and collects every recorded
// `requirement` property. The report is generated from the tests that actually
// executed, so it cannot drift the way a maintained matrix does.
[[nodiscard]] Result<RequirementsReport> buildRequirementsReport(const std::vector<DeclaredCriterion>& declared,
                                                                 const std::vector<std::filesystem::path>& testReports);

} // namespace rawframe::tool::verify
