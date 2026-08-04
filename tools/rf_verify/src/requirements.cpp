#include "requirements.h"

#include "json_reader.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rawframe::tool::verify {

namespace {

// GoogleTest reserves these keys, so a binding may not use one. The value below
// is the key STD-0007 names.
constexpr std::string_view kRequirementKey = "requirement";

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

// One test may discharge more than one criterion, and GoogleTest keeps one value
// per key, so several criteria arrive as one comma-separated value.
std::vector<std::string> splitCriteria(std::string_view value) {
    std::vector<std::string> parts;
    std::size_t offset = 0;
    while (offset <= value.size()) {
        const auto kSeparator = value.find(',', offset);
        const auto kPart = trim(
            value.substr(offset, kSeparator == std::string_view::npos ? std::string_view::npos : kSeparator - offset));
        if (!kPart.empty()) {
            parts.emplace_back(kPart);
        }
        if (kSeparator == std::string_view::npos) {
            break;
        }
        offset = kSeparator + 1;
    }
    return parts;
}

Status collectFromSuite(const JsonNode& suite,
                        std::map<std::string, std::set<std::string>>& bindings,
                        std::size_t& testsRead,
                        std::size_t& bindingsRead) {
    const JsonNode* cases = suite.find("testsuite");
    if (cases == nullptr || !cases->isArray()) {
        return {};
    }
    for (const auto& testCase : cases->elements) {
        if (!testCase.isObject()) {
            return reject(FailureCode::InvalidJson, {}, "a test case entry is not an object");
        }
        ++testsRead;
        const JsonNode* requirement = testCase.find(kRequirementKey);
        if (requirement == nullptr) {
            continue;
        }
        if (!requirement->isString()) {
            return reject(FailureCode::InvalidJson, {}, "a recorded requirement property is not a string");
        }
        const JsonNode* suiteName = testCase.find("classname");
        const JsonNode* caseName = testCase.find("name");
        if (suiteName == nullptr || !suiteName->isString() || caseName == nullptr || !caseName->isString()) {
            return reject(FailureCode::InvalidJson, {}, "a test case entry has no name");
        }
        const std::string kTestName = suiteName->text + "." + caseName->text;
        for (auto& criterion : splitCriteria(requirement->text)) {
            ++bindingsRead;
            bindings[std::move(criterion)].insert(kTestName);
        }
    }
    return {};
}

} // namespace

Result<std::vector<DeclaredCriterion>> readCriteriaInventory(const std::filesystem::path& path) {
    auto document = readJsonFile(path);
    if (!document) {
        return std::unexpected(document.error());
    }
    const JsonNode* criteria = document->find("criteria");
    if (criteria == nullptr || !criteria->isArray()) {
        return reject(FailureCode::InvalidJson, path.generic_string(), "the inventory has no criteria array");
    }

    std::vector<DeclaredCriterion> declared;
    std::set<std::string> seen;
    for (const auto& entry : criteria->elements) {
        const JsonNode* id = entry.find("id");
        const JsonNode* text = entry.find("text");
        const JsonNode* discharge = entry.find("discharge");
        if (id == nullptr || !id->isString() || text == nullptr || !text->isString() || discharge == nullptr ||
            !discharge->isString()) {
            return reject(
                FailureCode::InvalidJson, path.generic_string(), "a criterion needs an id, text, and discharge");
        }
        if (!id->text.contains(':')) {
            return reject(FailureCode::InvalidJson,
                          path.generic_string(),
                          "a criterion identifier must be <DOC-ID>:<criterion>: " + id->text);
        }
        if (!seen.insert(id->text).second) {
            return reject(FailureCode::InvalidJson,
                          path.generic_string(),
                          "the inventory declares one criterion twice: " + id->text);
        }

        DeclaredCriterion criterion;
        criterion.id = id->text;
        criterion.text = text->text;
        if (discharge->text == "automated") {
            criterion.discharge = DischargeKind::Automated;
        } else if (discharge->text == "manual") {
            criterion.discharge = DischargeKind::Manual;
            const JsonNode* procedure = entry.find("procedure");
            if (procedure == nullptr || !procedure->isString() || procedure->text.empty()) {
                return reject(FailureCode::InvalidJson,
                              path.generic_string(),
                              "a manually discharged criterion must name the procedure that discharges it: " +
                                  id->text);
            }
            criterion.procedure = procedure->text;
        } else if (discharge->text == "lane") {
            criterion.discharge = DischargeKind::Lane;
            const JsonNode* dischargedBy = entry.find("dischargedBy");
            if (dischargedBy == nullptr || !dischargedBy->isString() || dischargedBy->text.empty()) {
                return reject(FailureCode::InvalidJson,
                              path.generic_string(),
                              "a lane-discharged criterion must name what discharges it: " + id->text);
            }
            criterion.dischargedBy = dischargedBy->text;
            // The array is optional because a build target and a lane step are
            // both legitimate dischargers and neither is a CTest case. Present
            // and not an array of non-empty strings is a malformed inventory
            // rather than an absent one.
            if (const JsonNode* cases = entry.find("ctestCases"); cases != nullptr) {
                if (!cases->isArray()) {
                    return reject(FailureCode::InvalidJson,
                                  path.generic_string(),
                                  "a criterion's ctestCases must be an array: " + id->text);
                }
                for (const auto& element : cases->elements) {
                    if (!element.isString() || element.text.empty()) {
                        return reject(FailureCode::InvalidJson,
                                      path.generic_string(),
                                      "a criterion's ctestCases must each name one case: " + id->text);
                    }
                    criterion.ctestCases.push_back(element.text);
                }
            }
        } else {
            return reject(FailureCode::InvalidJson,
                          path.generic_string(),
                          "a criterion discharge must be automated, manual, or lane: " + discharge->text);
        }
        declared.push_back(std::move(criterion));
    }
    return declared;
}

Result<RequirementsReport> buildRequirementsReport(const std::vector<DeclaredCriterion>& declared,
                                                   const std::vector<std::filesystem::path>& testReports) {
    if (testReports.empty()) {
        return reject(FailureCode::InvalidArguments, {}, "a requirements report needs at least one test report");
    }

    std::map<std::string, std::set<std::string>> bindings;
    RequirementsReport report;
    for (const auto& path : testReports) {
        auto document = readJsonFile(path);
        if (!document) {
            return std::unexpected(document.error());
        }
        const JsonNode* suites = document->find("testsuites");
        if (suites == nullptr || !suites->isArray()) {
            return reject(FailureCode::InvalidJson, path.generic_string(), "the document is not a GoogleTest report");
        }
        for (const auto& suite : suites->elements) {
            if (auto status = collectFromSuite(suite, bindings, report.testsRead, report.bindingsRead); !status) {
                Failure failure = status.error();
                failure.path = path.generic_string();
                return std::unexpected(failure);
            }
        }
    }

    std::set<std::string> declaredIds;
    for (const auto& criterion : declared) {
        declaredIds.insert(criterion.id);
    }

    for (const auto& criterion : declared) {
        const auto kBinding = bindings.find(criterion.id);
        if (kBinding != bindings.end()) {
            CriterionBinding bound;
            bound.criterionId = criterion.id;
            bound.tests.assign(kBinding->second.begin(), kBinding->second.end());
            report.bound.push_back(std::move(bound));
            continue;
        }
        if (criterion.discharge == DischargeKind::Manual) {
            report.manual.push_back(criterion);
            continue;
        }
        if (criterion.discharge == DischargeKind::Lane) {
            report.lane.push_back(criterion);
            continue;
        }
        report.unbound.push_back(criterion);
    }

    for (const auto& [criterionId, tests] : bindings) {
        if (declaredIds.contains(criterionId)) {
            continue;
        }
        CriterionBinding undeclared;
        undeclared.criterionId = criterionId;
        undeclared.tests.assign(tests.begin(), tests.end());
        report.findings.report(kRuleUndeclaredCriterion,
                               undeclared.tests.front(),
                               "a test binds a criterion the inventory does not declare: " + criterionId);
        report.undeclared.push_back(std::move(undeclared));
    }

    return report;
}

} // namespace rawframe::tool::verify
