#include "rule_corpus.h"

#include "tool_limits.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <system_error>
#include <utility>

namespace rawframe::tool::archcheck {

namespace {

std::unexpected<Failure> reject(std::string message) {
    return std::unexpected(Failure{FailureCode::InvalidCorpus, {}, std::move(message)});
}

constexpr std::array kMemberNames{
    std::string_view{"id"},
    std::string_view{"authority"},
    std::string_view{"title"},
    std::string_view{"subjectKind"},
    std::string_view{"severity"},
    std::string_view{"landsWith"},
};

constexpr std::array kSubjectKinds{
    std::string_view{"manifest"},
    std::string_view{"module_root"},
    std::string_view{"target_closure"},
    std::string_view{"source_file"},
    std::string_view{"build_file"},
    std::string_view{"declared_edge"},
    std::string_view{"projection"},
    std::string_view{"repository"},
};

bool isRuleId(std::string_view id) {
    if (id.size() != 6 || !id.starts_with("RA")) {
        return false;
    }
    if (id.at(2) < '1' || id.at(2) > '7') {
        return false;
    }
    for (std::size_t index = 3; index < id.size(); ++index) {
        if (id.at(index) < '0' || id.at(index) > '9') {
            return false;
        }
    }
    return true;
}

bool isAuthorityIdentifier(std::string_view authority) {
    const auto kSeparator = authority.find('.');
    if (kSeparator == std::string_view::npos) {
        return false;
    }
    const std::string_view kPrefix = authority.substr(0, kSeparator);
    const std::string_view kNumber = authority.substr(kSeparator + 1);
    if (kPrefix != "adr" && kPrefix != "spec" && kPrefix != "std") {
        return false;
    }
    if (kNumber.size() != 4) {
        return false;
    }
    return std::ranges::all_of(kNumber, [](char digit) {
        return digit >= '0' && digit <= '9';
    });
}

bool isLandsWith(std::string_view value) {
    if (value == "now") {
        return true;
    }
    if (value.size() != 9 || !value.starts_with("TASK-")) {
        return false;
    }
    for (std::size_t index = 5; index < value.size(); ++index) {
        if (value.at(index) < '0' || value.at(index) > '9') {
            return false;
        }
    }
    return true;
}

Result<std::string> requiredString(const JsonNode& object, std::string_view key) {
    const JsonNode* member = object.find(key);
    if (member == nullptr || !member->isString()) {
        return reject("rule member is absent or not a string: " + std::string(key));
    }
    return member->text;
}

Result<std::int64_t> requiredInteger(const JsonNode& object, std::string_view key) {
    const JsonNode* member = object.find(key);
    if (member == nullptr || member->kind != JsonKind::Number) {
        return reject("corpus member is absent or not a number: " + std::string(key));
    }
    std::int64_t parsed = 0;
    const auto kResult = std::from_chars(member->text.data(), member->text.data() + member->text.size(), parsed);
    if (kResult.ec != std::errc{} || kResult.ptr != member->text.data() + member->text.size()) {
        return reject("corpus member is not an integer: " + std::string(key));
    }
    return parsed;
}

} // namespace

const Rule* RuleCorpus::find(std::string_view id) const noexcept {
    for (const auto& rule : rules) {
        if (rule.id == id) {
            return &rule;
        }
    }
    return nullptr;
}

std::string sealRules(const std::vector<Rule>& rules) {
    // The sealed payload is the six member values of every rule in array order,
    // separated by the unit separator and terminated by the record separator.
    // Two characters no rule text may contain, so the payload cannot be forged
    // by writing a separator into a title.
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    const auto kAbsorb = [&hash](std::string_view text) {
        for (const char kCharacter : text) {
            hash ^= static_cast<unsigned char>(kCharacter);
            hash *= 0x100000001b3ULL;
        }
    };
    for (const auto& rule : rules) {
        for (const std::string_view kValue : {std::string_view{rule.id},
                                              std::string_view{rule.authority},
                                              std::string_view{rule.title},
                                              std::string_view{rule.subjectKind},
                                              std::string_view{rule.severity},
                                              std::string_view{rule.landsWith}}) {
            kAbsorb(kValue);
            kAbsorb(std::string_view{"\x1f", 1});
        }
        kAbsorb(std::string_view{"\x1e", 1});
    }
    // Sixteen lowercase hex digits, most significant first, written out
    // rather than formatted, because the seal is compared byte for byte and a
    // width-defaulted formatter would be a second definition of the same value.
    constexpr std::string_view kHexDigits = "0123456789abcdef";
    std::string sealed = "fnv1a64:";
    for (int shift = 60; shift >= 0; shift -= 4) {
        sealed.push_back(kHexDigits.at((hash >> static_cast<unsigned>(shift)) & 0x0FULL));
    }
    return sealed;
}

Result<RuleCorpus> parseRuleCorpus(const JsonNode& root) {
    if (!root.isObject()) {
        return reject("the rule corpus is not an object");
    }
    RuleCorpus corpus;
    auto policyVersion = requiredInteger(root, "policyVersion");
    if (!policyVersion) {
        return std::unexpected(policyVersion.error());
    }
    corpus.policyVersion = *policyVersion;
    if (corpus.policyVersion < 1) {
        return reject("policyVersion must be a positive integer");
    }
    auto seal = requiredString(root, "ruleSetSeal");
    if (!seal) {
        return std::unexpected(seal.error());
    }
    corpus.ruleSetSeal = *seal;

    const JsonNode* history = root.find("policyHistory");
    if (history == nullptr || !history->isArray() || history->elements.empty()) {
        return reject("policyHistory is absent or empty");
    }
    for (const auto& entry : history->elements) {
        if (!entry.isObject()) {
            return reject("policyHistory carries a non-object entry");
        }
        auto version = requiredInteger(entry, "policyVersion");
        if (!version) {
            return std::unexpected(version.error());
        }
        auto entrySeal = requiredString(entry, "ruleSetSeal");
        if (!entrySeal) {
            return std::unexpected(entrySeal.error());
        }
        if (!corpus.policyHistory.empty() && *version <= corpus.policyHistory.back().policyVersion) {
            return reject("policyHistory versions do not increase");
        }
        corpus.policyHistory.push_back(PolicyHistoryEntry{*version, std::move(*entrySeal)});
    }

    const JsonNode* rules = root.find("rules");
    if (rules == nullptr || !rules->isArray() || rules->elements.empty()) {
        return reject("rules is absent or empty");
    }
    if (rules->elements.size() > kMaximumRules) {
        return reject("rules exceeds the corpus limit");
    }
    for (const auto& element : rules->elements) {
        if (!element.isObject()) {
            return reject("rules carries a non-object entry");
        }
        // Exactly the six named members and no others. An extra member is a rule
        // carrying meaning the corpus grammar does not define, and a missing one
        // is a rule that cannot be evaluated; both are load failures rather than
        // fields to ignore.
        if (element.members.size() != kMemberNames.size()) {
            return reject("a rule does not carry exactly the six defined members");
        }
        for (const std::string_view kName : kMemberNames) {
            if (element.find(kName) == nullptr) {
                return reject("a rule is missing the member: " + std::string(kName));
            }
        }
        Rule rule;
        std::array<std::string*, kMemberNames.size()> targets{
            &rule.id, &rule.authority, &rule.title, &rule.subjectKind, &rule.severity, &rule.landsWith};
        for (std::size_t index = 0; index < kMemberNames.size(); ++index) {
            auto value = requiredString(element, kMemberNames.at(index));
            if (!value) {
                return std::unexpected(value.error());
            }
            *targets.at(index) = std::move(*value);
        }
        if (!isRuleId(rule.id)) {
            return reject("a rule identity does not match the required form: " + rule.id);
        }
        if (!isAuthorityIdentifier(rule.authority)) {
            return reject("rule " + rule.id + " does not cite exactly one accepted authority: " + rule.authority);
        }
        if (rule.title.size() < 20) {
            return reject("rule " + rule.id + " has no usable title");
        }
        bool knownSubject = false;
        for (const std::string_view kKind : kSubjectKinds) {
            knownSubject = knownSubject || rule.subjectKind == kKind;
        }
        if (!knownSubject) {
            return reject("rule " + rule.id + " has an unknown subject kind: " + rule.subjectKind);
        }
        if (rule.severity != "finding") {
            return reject("rule " + rule.id + " declares a severity other than finding");
        }
        if (!isLandsWith(rule.landsWith)) {
            return reject("rule " + rule.id + " has an unusable landsWith value: " + rule.landsWith);
        }
        if (!corpus.rules.empty() && corpus.rules.back().id >= rule.id) {
            return reject("rules are not ordered by identity without duplicates at: " + rule.id);
        }
        corpus.rules.push_back(std::move(rule));
    }
    return corpus;
}

Result<RuleCorpus> loadRuleCorpus(const std::filesystem::path& corpusPath) {
    auto document = readJsonDocument(corpusPath);
    if (!document) {
        auto failure = document.error();
        if (failure.code == FailureCode::InvalidJson) {
            failure.code = FailureCode::InvalidCorpus;
        }
        return std::unexpected(failure);
    }
    auto corpus = parseRuleCorpus(document->root);
    if (!corpus) {
        auto failure = corpus.error();
        failure.path = corpusPath.generic_string();
        return std::unexpected(failure);
    }
    return corpus;
}

} // namespace rawframe::tool::archcheck
