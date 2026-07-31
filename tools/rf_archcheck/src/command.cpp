#include "command.h"

#include "engine.h"
#include "json_reader.h"
#include "repository_scan.h"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <iterator>
#include <system_error>
#include <utility>
#include <vector>

namespace rawframe::tool::archcheck {

namespace {

constexpr std::string_view kDefaultCorpusPath = "tools/rf_archcheck/rules/architecture-rules.json";

constexpr std::string_view kUsage =
    "usage:\n"
    "  rf-archcheck check_repository --root <path> [--corpus <repository-relative path>] [--report <path>]\n"
    "  rf-archcheck explain_rule --root <path> --rule <RAnnnn> [--corpus <repository-relative path>]\n"
    "  rf-archcheck list_rules --root <path> [--corpus <repository-relative path>]\n";

CommandOutput usageError(std::string message) {
    CommandOutput output;
    output.exitClass = ExitClass::UsageError;
    output.standardError = std::move(message) + "\n" + std::string(kUsage);
    return output;
}

CommandOutput internalError(const Failure& failure) {
    CommandOutput output;
    output.exitClass = ExitClass::InternalError;
    output.standardError = std::string("rf-archcheck: ") + failureCodeName(failure.code) + ": " +
                           (failure.path.empty() ? std::string("(no path)") : failure.path) + ": " + failure.message +
                           "\n";
    return output;
}

struct Options {
    std::filesystem::path root;
    std::string corpus{kDefaultCorpusPath};
    std::string rule;
    std::filesystem::path report;
    bool hasReport = false;
};

using ArgumentIterator = std::span<const std::string_view>::iterator;

// A value option consumes the next argument. An option without its value is a
// usage error rather than a default, because a default here would silently
// check something other than what was asked for. The absent value is reported
// as an empty string, which every caller rejects.
bool takeValue(std::span<const std::string_view> arguments,
               ArgumentIterator& current,
               std::string_view name,
               std::string& target) {
    if (*current != name) {
        return false;
    }
    const auto kFollowing = std::next(current);
    if (kFollowing == arguments.end()) {
        // The option ends the command line. `current` stays where it is so that
        // the caller's loop reaches the end by its own increment.
        target.clear();
        return true;
    }
    target = std::string(*kFollowing);
    current = kFollowing;
    return true;
}

std::string escapeForReport(std::string_view text) {
    std::string escaped;
    for (const char kCharacter : text) {
        if (kCharacter == '\n' || kCharacter == '\r') {
            escaped.push_back(' ');
            continue;
        }
        escaped.push_back(kCharacter);
    }
    return escaped;
}

Status writeReport(const std::filesystem::path& path, std::string_view bytes) {
    std::error_code code;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), code);
        if (code) {
            return std::unexpected(
                Failure{FailureCode::IoFailure, path.generic_string(), "cannot create the report directory"});
        }
    }
    std::FILE* handle = nullptr;
#ifdef _WIN32
    if (::_wfopen_s(&handle, path.c_str(), L"wb") != 0 || handle == nullptr) {
        return std::unexpected(Failure{FailureCode::IoFailure, path.generic_string(), "cannot open the report"});
    }
#else
    handle = std::fopen(path.c_str(), "wb");
    if (handle == nullptr) {
        return std::unexpected(Failure{FailureCode::IoFailure, path.generic_string(), "cannot open the report"});
    }
#endif
    const std::size_t kWritten = std::fwrite(bytes.data(), 1, bytes.size(), handle);
    const bool kFailed = std::ferror(handle) != 0;
    (void)std::fclose(handle);
    if (kFailed || kWritten != bytes.size()) {
        return std::unexpected(Failure{FailureCode::IoFailure, path.generic_string(), "cannot write the report"});
    }
    return {};
}

CommandOutput runCheckRepository(const Options& options) {
    auto outcome = checkRepository(options.root, options.root / options.corpus, options.corpus);
    if (!outcome) {
        return internalError(outcome.error());
    }
    const std::string kDocument = renderFindingsDocument(outcome->policyVersion, outcome->findings);
    if (options.hasReport) {
        if (auto status = writeReport(options.report, kDocument); !status) {
            return internalError(status.error());
        }
    }
    CommandOutput output;
    output.standardOutput = kDocument;
    output.exitClass = outcome->findings.empty() ? ExitClass::Clean : ExitClass::Findings;
    return output;
}

CommandOutput runListRules(const Options& options) {
    auto corpus = loadRuleCorpus(options.root / options.corpus);
    if (!corpus) {
        return internalError(corpus.error());
    }
    auto model = loadRepositoryModel(options.root, options.corpus);
    if (!model) {
        return internalError(model.error());
    }
    const std::vector<SubjectCount> kCounts = countSubjects(*model, *corpus);

    CommandOutput output;
    output.standardOutput = "policyVersion " + std::to_string(corpus->policyVersion) + "\n";
    output.standardOutput += "ruleSetSeal " + corpus->ruleSetSeal + "\n";
    for (const auto& rule : corpus->rules) {
        const auto kCount = std::ranges::find_if(kCounts, [&rule](const SubjectCount& count) {
            return count.ruleId == rule.id;
        });
        const std::size_t kSubjects = kCount == kCounts.end() ? 0 : kCount->subjects;
        output.standardOutput += rule.id + " " + rule.authority + " " + rule.landsWith +
                                 " subjects=" + std::to_string(kSubjects) + " " + escapeForReport(rule.title) + "\n";
    }
    return output;
}

CommandOutput runExplainRule(const Options& options) {
    auto corpus = loadRuleCorpus(options.root / options.corpus);
    if (!corpus) {
        return internalError(corpus.error());
    }
    const Rule* rule = corpus->find(options.rule);
    if (rule == nullptr) {
        return usageError("no such rule in the corpus: " + options.rule);
    }
    CommandOutput output;
    output.standardOutput = "id " + rule->id + "\n";
    output.standardOutput += "authority " + rule->authority + "\n";
    output.standardOutput += "subjectKind " + rule->subjectKind + "\n";
    output.standardOutput += "severity " + rule->severity + "\n";
    output.standardOutput += "landsWith " + rule->landsWith + "\n";
    output.standardOutput += "policyVersion " + std::to_string(corpus->policyVersion) + "\n";
    output.standardOutput += "title " + escapeForReport(rule->title) + "\n";
    return output;
}

} // namespace

CommandOutput runCommand(std::span<const std::string_view> arguments) {
    if (arguments.empty()) {
        return usageError("no operation was named");
    }
    const std::string_view kOperation = arguments.front();
    Options options;
    std::string root;
    std::string report;
    for (auto current = std::next(arguments.begin()); current != arguments.end(); ++current) {
        std::string value;
        if (takeValue(arguments, current, "--root", value)) {
            root = value;
            continue;
        }
        if (takeValue(arguments, current, "--corpus", value)) {
            options.corpus = value;
            continue;
        }
        if (takeValue(arguments, current, "--rule", value)) {
            options.rule = value;
            continue;
        }
        if (takeValue(arguments, current, "--report", value)) {
            report = value;
            options.hasReport = true;
            continue;
        }
        return usageError("unknown option: " + std::string(*current));
    }
    if (root.empty()) {
        return usageError("--root is required and takes a value");
    }
    if (options.corpus.empty()) {
        return usageError("--corpus takes a value");
    }
    if (options.hasReport && report.empty()) {
        return usageError("--report takes a value");
    }
    options.root = std::filesystem::path(root);
    options.report = std::filesystem::path(report);

    if (kOperation == "check_repository") {
        return runCheckRepository(options);
    }
    if (kOperation == "list_rules") {
        return runListRules(options);
    }
    if (kOperation == "explain_rule") {
        if (options.rule.empty()) {
            return usageError("--rule is required and takes a value");
        }
        return runExplainRule(options);
    }
    return usageError("unknown operation: " + std::string(kOperation));
}

} // namespace rawframe::tool::archcheck
