#include "command.h"

#include "coverage_export.h"
#include "coverage_summary.h"
#include "diff_reader.h"
#include "failure.h"
#include "findings.h"
#include "floors.h"
#include "report_writer.h"
#include "repository_paths.h"
#include "requirements.h"
#include "tier_declarations.h"

#include <filesystem>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rawframe::tool::verify {

namespace {

constexpr std::string_view kDefaultCriteriaPath = "tools/rf_verify/criteria/acceptance-criteria.json";

struct Options {
    std::string_view operation;
    std::filesystem::path repositoryRoot{"."};
    std::vector<std::filesystem::path> coverageExports;
    std::filesystem::path diff;
    std::filesystem::path criteria;
    std::vector<std::filesystem::path> testReports;
    std::filesystem::path report;
};

std::unexpected<Failure> reject(FailureCode code, std::string path, std::string message) {
    return std::unexpected(Failure{code, std::move(path), std::move(message)});
}

Result<Options> parseOptions(std::span<const std::string_view> arguments) {
    if (arguments.empty()) {
        return reject(FailureCode::InvalidArguments,
                      {},
                      "an operation is required: coverage_floors, coverage_summary, or requirements_report");
    }

    Options options;
    options.operation = arguments.front();
    for (auto current = std::next(arguments.begin()); current != arguments.end(); ++current) {
        const std::string_view kFlag = *current;
        const auto kFollowing = std::next(current);
        const bool kHasValue = kFollowing != arguments.end();
        // Taking a value advances past it, and the loop's own increment then
        // moves on to the next option. An option with no value falls through to
        // the rejection below rather than acquiring a default, because a default
        // here would measure something other than what was asked for.
        auto takeValue = [&]() -> std::string_view {
            current = kFollowing;
            return *kFollowing;
        };

        if (kFlag == "--root" && kHasValue) {
            options.repositoryRoot = std::filesystem::path(takeValue());
        } else if (kFlag == "--export" && kHasValue) {
            options.coverageExports.emplace_back(takeValue());
        } else if (kFlag == "--diff" && kHasValue) {
            options.diff = std::filesystem::path(takeValue());
        } else if (kFlag == "--criteria" && kHasValue) {
            options.criteria = std::filesystem::path(takeValue());
        } else if (kFlag == "--test-report" && kHasValue) {
            options.testReports.emplace_back(takeValue());
        } else if (kFlag == "--report" && kHasValue) {
            options.report = std::filesystem::path(takeValue());
        } else {
            return reject(
                FailureCode::InvalidArguments, {}, "unrecognized or incomplete argument: " + std::string(kFlag));
        }
    }
    return options;
}

void writeFindings(JsonWriter& writer, const FindingSet& findings) {
    writer.key("findings");
    writer.beginArray();
    for (const auto& finding : findings.findings) {
        writer.beginObject();
        writer.member("ruleId", finding.ruleId);
        writer.member("path", finding.path);
        writer.member("message", finding.message);
        writer.endObject();
    }
    writer.endArray();
    writer.member("findingCount", static_cast<std::int64_t>(findings.findings.size()));
}

void writeCounts(JsonWriter& writer, std::string_view name, const CoverageCounts& counts) {
    writer.key(name);
    writer.beginObject();
    writer.member("count", counts.count);
    writer.member("covered", counts.covered);
    writer.endObject();
}

int emit(
    std::ostream& output, std::ostream& errors, const Options& options, const std::string& document, bool conformant) {
    if (!options.report.empty()) {
        std::filesystem::path root = options.repositoryRoot;
        if (auto resolved = resolveRepositoryRoot(root); resolved) {
            root = *resolved;
        }
        if (auto status = writeReportFile(root, options.report, document); !status) {
            errors << "{\"ok\":false,\"failure\":\"" << failureCodeName(status.error().code) << "\",\"path\":\""
                   << status.error().path << "\",\"message\":\"" << status.error().message << "\"}\n";
            return kExitToolFailure;
        }
    }
    output << document;
    return conformant ? kExitConformant : kExitFindings;
}

int fail(std::ostream& errors, const Failure& failure) {
    errors << "{\"ok\":false,\"failure\":\"" << failureCodeName(failure.code) << "\",\"path\":\"" << failure.path
           << "\",\"message\":\"" << failure.message << "\"}\n";
    return isUsageFailure(failure.code) ? kExitUsage : kExitToolFailure;
}

int coverageFloors(const Options& options, std::ostream& output, std::ostream& errors) {
    if (options.coverageExports.empty() || options.diff.empty()) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments,
                            {},
                            "coverage_floors requires --export and --diff; a floor verdict with no changed-line set "
                            "would be a whole-tree gate under a diff-scoped name"});
    }
    auto root = resolveRepositoryRoot(options.repositoryRoot);
    if (!root) {
        return fail(errors, root.error());
    }
    auto coverage = readCoverageExports(*root, options.coverageExports);
    if (!coverage) {
        return fail(errors, coverage.error());
    }
    auto changed = readUnifiedDiff(options.diff);
    if (!changed) {
        return fail(errors, changed.error());
    }
    if (changed->empty()) {
        return fail(errors,
                    Failure{FailureCode::NoChangedLines,
                            options.diff.generic_string(),
                            "the diff names no added or modified line, so there is nothing for a diff-scoped floor to "
                            "measure"});
    }
    auto tiers = readTierIndex(*root);
    if (!tiers) {
        return fail(errors, tiers.error());
    }
    auto evaluation = evaluateFloors(*changed, *coverage, *tiers);
    if (!evaluation) {
        return fail(errors, evaluation.error());
    }

    std::ostringstream document;
    JsonWriter writer(document);
    writer.beginObject();
    writer.member("report", std::string_view{"coverage_floors"});
    writer.member("authority", std::string_view{"STD-0007"});
    writer.member("evidenceClass", std::string_view{"correctness_and_hygiene"});
    writer.member("producerVersion", coverage->producerVersion);
    writer.member("changedNonSourcePaths", static_cast<std::int64_t>(evaluation->changedNonSourcePaths));
    writer.member("changedHeadersWithoutInstrumentedCode",
                  static_cast<std::int64_t>(evaluation->changedHeadersWithoutInstrumentedCode));
    writer.key("units");
    writer.beginArray();
    for (const auto& unit : evaluation->units) {
        writer.beginObject();
        writer.member("path", unit.path);
        writer.member("tier", tierName(unit.tier));
        writer.member("floorPercent", static_cast<std::int64_t>(unit.floorPercent));
        writer.member("changedBranchConditions", unit.changedConditions);
        writer.member("coveredBranchConditions", unit.coveredConditions);
        writer.member("meetsFloor", unit.meetsFloor);
        writer.member("changedDecisions", static_cast<std::int64_t>(unit.changedDecisions));
        writer.member("uncoveredDecisions", static_cast<std::int64_t>(unit.uncoveredDecisions));
        writer.key("partiallyCoveredBranchLines");
        writer.writeIntegerArray(unit.uncoveredBranchLines);
        writer.endObject();
    }
    writer.endArray();
    writeFindings(writer, evaluation->findings);
    writer.endObject();
    document << '\n';

    return emit(output, errors, options, document.str(), evaluation->findings.empty());
}

int coverageSummary(const Options& options, std::ostream& output, std::ostream& errors) {
    if (options.coverageExports.empty()) {
        return fail(errors, Failure{FailureCode::InvalidArguments, {}, "coverage_summary requires --export"});
    }
    auto root = resolveRepositoryRoot(options.repositoryRoot);
    if (!root) {
        return fail(errors, root.error());
    }
    auto coverage = readCoverageExports(*root, options.coverageExports);
    if (!coverage) {
        return fail(errors, coverage.error());
    }
    auto tiers = readTierIndex(*root);
    if (!tiers) {
        return fail(errors, tiers.error());
    }
    auto summary = summarizeCoverage(*coverage, *tiers);
    if (!summary) {
        return fail(errors, summary.error());
    }

    std::ostringstream document;
    JsonWriter writer(document);
    writer.beginObject();
    writer.member("report", std::string_view{"coverage_summary"});
    writer.member("authority", std::string_view{"STD-0007"});
    writer.member("evidenceClass", std::string_view{"correctness_and_hygiene"});
    writer.member("budgetClass", std::string_view{"verification_objective"});
    writer.member("producerVersion", coverage->producerVersion);
    writer.member("droppedForeignFiles", static_cast<std::int64_t>(summary->droppedForeignFiles));
    writer.member("omittedUncoveredLines", static_cast<std::int64_t>(summary->omittedUncoveredLines));
    writer.key("totals");
    writer.beginObject();
    writeCounts(writer, "lines", summary->totals.lines);
    writeCounts(writer, "branches", summary->totals.branches);
    writeCounts(writer, "regions", summary->totals.regions);
    writeCounts(writer, "mcdc", summary->totals.mcdc);
    writer.endObject();
    writer.key("files");
    writer.beginArray();
    for (const auto& file : summary->files) {
        writer.beginObject();
        writer.member("path", file.path);
        writer.member("tier", file.tier);
        writeCounts(writer, "lines", file.counts.lines);
        writeCounts(writer, "branches", file.counts.branches);
        writeCounts(writer, "mcdc", file.counts.mcdc);
        writer.key("uncoveredLines");
        writer.writeIntegerArray(file.uncoveredLines);
        writer.key("partiallyCoveredBranchLines");
        writer.writeIntegerArray(file.partiallyCoveredBranchLines);
        writer.key("uncoveredDecisionLines");
        writer.writeIntegerArray(file.uncoveredDecisionLines);
        writer.endObject();
    }
    writer.endArray();
    writer.endObject();
    document << '\n';

    return emit(output, errors, options, document.str(), true);
}

int requirementsReport(const Options& options, std::ostream& output, std::ostream& errors) {
    if (options.testReports.empty()) {
        return fail(errors,
                    Failure{FailureCode::InvalidArguments,
                            {},
                            "requirements_report requires at least one --test-report; the report is generated from the "
                            "tests that executed and never from a maintained matrix"});
    }
    auto root = resolveRepositoryRoot(options.repositoryRoot);
    if (!root) {
        return fail(errors, root.error());
    }
    const auto kCriteriaPath =
        options.criteria.empty() ? *root / std::filesystem::path(kDefaultCriteriaPath) : options.criteria;
    auto declared = readCriteriaInventory(kCriteriaPath);
    if (!declared) {
        return fail(errors, declared.error());
    }
    auto report = buildRequirementsReport(*declared, options.testReports);
    if (!report) {
        return fail(errors, report.error());
    }

    std::ostringstream document;
    JsonWriter writer(document);
    writer.beginObject();
    writer.member("report", std::string_view{"requirements_report"});
    writer.member("authority", std::string_view{"STD-0007"});
    writer.member("evidenceClass", std::string_view{"correctness_and_hygiene"});
    writer.member("testsRead", static_cast<std::int64_t>(report->testsRead));
    writer.member("bindingsRead", static_cast<std::int64_t>(report->bindingsRead));
    writer.member("declaredCriteria", static_cast<std::int64_t>(declared->size()));
    writer.member("boundCriteria", static_cast<std::int64_t>(report->bound.size()));
    writer.member("unboundCriteria", static_cast<std::int64_t>(report->unbound.size()));
    writer.member("manuallyDischargedCriteria", static_cast<std::int64_t>(report->manual.size()));
    writer.key("bound");
    writer.beginArray();
    for (const auto& binding : report->bound) {
        writer.beginObject();
        writer.member("criterion", binding.criterionId);
        writer.key("tests");
        writer.writeStringArray(binding.tests);
        writer.endObject();
    }
    writer.endArray();
    writer.key("unbound");
    writer.beginArray();
    for (const auto& criterion : report->unbound) {
        writer.beginObject();
        writer.member("criterion", criterion.id);
        writer.member("text", criterion.text);
        writer.endObject();
    }
    writer.endArray();
    writer.key("manual");
    writer.beginArray();
    for (const auto& criterion : report->manual) {
        writer.beginObject();
        writer.member("criterion", criterion.id);
        writer.member("procedure", criterion.procedure);
        writer.endObject();
    }
    writer.endArray();
    writer.key("undeclared");
    writer.beginArray();
    for (const auto& binding : report->undeclared) {
        writer.beginObject();
        writer.member("criterion", binding.criterionId);
        writer.key("tests");
        writer.writeStringArray(binding.tests);
        writer.endObject();
    }
    writer.endArray();
    writeFindings(writer, report->findings);
    writer.endObject();
    document << '\n';

    return emit(output, errors, options, document.str(), report->findings.empty());
}

} // namespace

int runCommand(std::span<const std::string_view> arguments, std::ostream& output, std::ostream& errors) {
    auto options = parseOptions(arguments);
    if (!options) {
        return fail(errors, options.error());
    }
    if (options->operation == "coverage_floors") {
        return coverageFloors(*options, output, errors);
    }
    if (options->operation == "coverage_summary") {
        return coverageSummary(*options, output, errors);
    }
    if (options->operation == "requirements_report") {
        return requirementsReport(*options, output, errors);
    }
    return fail(errors,
                Failure{FailureCode::InvalidArguments, {}, "unknown operation: " + std::string(options->operation)});
}

} // namespace rawframe::tool::verify
