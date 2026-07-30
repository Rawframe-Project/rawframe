#include "findings.h"

#include "json_reader.h"
#include "tool_limits.h"

#include <algorithm>
#include <string>
#include <utility>

namespace rawframe::tool::archcheck {

namespace {

JsonNode makeString(std::string text) {
    JsonNode node;
    node.kind = JsonKind::String;
    node.text = std::move(text);
    return node;
}

JsonNode makeNumber(std::int64_t value) {
    JsonNode node;
    node.kind = JsonKind::Number;
    node.text = std::to_string(value);
    return node;
}

} // namespace

void FindingSink::report(std::string_view ruleId, std::string subject, std::string detail) {
    reportAt(ruleId, std::move(subject), Position{}, std::move(detail));
}

void FindingSink::reportAt(std::string_view ruleId, std::string subject, Position position, std::string detail) {
    const Rule* rule = corpus_->find(ruleId);
    if (rule == nullptr) {
        unknownRule_ = true;
        return;
    }
    if (findings_.size() >= kMaximumFindings) {
        overflowed_ = true;
        return;
    }
    findings_.push_back(Finding{rule->id, rule->authority, std::move(subject), position, std::move(detail)});
}

bool findingPrecedes(const Finding& left, const Finding& right) noexcept {
    if (left.ruleId != right.ruleId) {
        return left.ruleId < right.ruleId;
    }
    if (left.subject != right.subject) {
        return left.subject < right.subject;
    }
    if (left.position.line != right.position.line) {
        return left.position.line < right.position.line;
    }
    if (left.position.column != right.position.column) {
        return left.position.column < right.position.column;
    }
    return left.detail < right.detail;
}

void sortFindings(std::vector<Finding>& findings) {
    std::ranges::stable_sort(findings, findingPrecedes);
}

std::string renderFindingsDocument(std::int64_t policyVersion, const std::vector<Finding>& findings) {
    JsonNode document;
    document.kind = JsonKind::Object;
    document.members.emplace_back("$schema", makeString("../../schemas/archcheck-findings-v1.schema.json"));
    document.members.emplace_back("schemaVersion", makeNumber(1));
    document.members.emplace_back("policyVersion", makeNumber(policyVersion));
    document.members.emplace_back("toolVersion", makeString(std::string(kToolVersion)));
    document.members.emplace_back("findingCount", makeNumber(static_cast<std::int64_t>(findings.size())));

    JsonNode list;
    list.kind = JsonKind::Array;
    for (const auto& finding : findings) {
        JsonNode entry;
        entry.kind = JsonKind::Object;
        entry.members.emplace_back("ruleId", makeString(finding.ruleId));
        entry.members.emplace_back("authority", makeString(finding.authority));
        entry.members.emplace_back("subject", makeString(finding.subject));
        if (finding.position.present()) {
            JsonNode position;
            position.kind = JsonKind::Object;
            position.members.emplace_back("line", makeNumber(static_cast<std::int64_t>(finding.position.line)));
            position.members.emplace_back("column", makeNumber(static_cast<std::int64_t>(finding.position.column)));
            entry.members.emplace_back("position", std::move(position));
        }
        entry.members.emplace_back("detail", makeString(finding.detail));
        list.elements.push_back(std::move(entry));
    }
    document.members.emplace_back("findings", std::move(list));

    std::string rendered = serializeMaintainedForm(document);
    rendered.push_back('\n');
    return rendered;
}

} // namespace rawframe::tool::archcheck
