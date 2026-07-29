#include "raw_run_receipt.h"

#include <vector>

namespace rawframe::tool::evidence {

namespace {

std::unexpected<RecordFailure> reject(RecordRejection rejection, std::string detail) {
    return std::unexpected(RecordFailure{rejection, std::move(detail)});
}

std::size_t countAt(const CanonicalValue& record, std::string_view group, std::string_view member) {
    const auto* kGroup = record.find(group);
    if (kGroup == nullptr) {
        return 0;
    }
    const auto* kArray = kGroup->find(member);
    if (kArray == nullptr || kArray->kind() != CanonicalValue::Kind::Array) {
        return 0;
    }
    return kArray->elements().size();
}

std::string textAt(const CanonicalValue& record, std::string_view group, std::string_view member) {
    const CanonicalValue* kValue = nullptr;
    if (group.empty()) {
        kValue = record.find(member);
    } else if (const auto* kGroup = record.find(group); kGroup != nullptr) {
        kValue = kGroup->find(member);
    }
    if (kValue == nullptr || kValue->kind() != CanonicalValue::Kind::String) {
        return {};
    }
    return kValue->text();
}

std::string emitObject(std::vector<CanonicalValue::Member> members) {
    return serializeCanonical(CanonicalValue::makeObject(std::move(members)));
}

std::vector<CanonicalValue::Member> summaryMembers(const Descriptor& descriptor, const RawRunReceiptSummary& summary) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("ok", CanonicalValue::makeBoolean(true));
    members.emplace_back("descriptor", describeAsValue(descriptor));
    members.emplace_back("runId", CanonicalValue::makeString(summary.runId));
    members.emplace_back("status", CanonicalValue::makeString(summary.status));
    members.emplace_back("provenance", CanonicalValue::makeString(summary.provenance));
    members.emplace_back("metricCount", CanonicalValue::makeInteger(static_cast<std::int64_t>(summary.metricCount)));
    members.emplace_back("lifecycleEventCount",
                         CanonicalValue::makeInteger(static_cast<std::int64_t>(summary.lifecycleEventCount)));
    members.emplace_back("attachmentCount",
                         CanonicalValue::makeInteger(static_cast<std::int64_t>(summary.attachmentCount)));
    return members;
}

} // namespace

RecordStatus checkSchema(const std::filesystem::path& repositoryRoot, const std::filesystem::path& instancePath) {
    return validateAgainstSchema(repositoryRoot, kRawRunReceiptSchemaPath, instancePath);
}

RecordStatus checkGenerationAgreement(const CanonicalValue& record, std::string_view mediaType) {
    return checkGenerationMatches(record, mediaType, kRawRunReceiptGeneration);
}

RecordResult<RawRunReceiptSummary> summarizeRawRunReceipt(const CanonicalValue& record) {
    if (record.kind() != CanonicalValue::Kind::Object) {
        return reject(RecordRejection::SchemaInvalid, "record is not an object");
    }
    RawRunReceiptSummary summary;
    summary.runId = textAt(record, {}, "runId");
    summary.status = textAt(record, {}, "status");
    summary.provenance = textAt(record, "trust", "provenance");
    summary.metricCount = countAt(record, "observations", "metrics");
    summary.lifecycleEventCount = countAt(record, "observations", "lifecycleEvents");
    summary.attachmentCount = countAt(record, "observations", "attachments");
    if (summary.runId.empty() || summary.status.empty() || summary.provenance.empty()) {
        return reject(RecordRejection::SchemaInvalid, "record is missing a required identity member");
    }
    return summary;
}

RecordResult<RawRunReceiptSummary> validateRawRunReceipt(const std::filesystem::path& repositoryRoot,
                                                         const std::filesystem::path& instancePath,
                                                         const CanonicalValue& record,
                                                         std::string_view mediaType) {
    if (auto status = checkProducerAuthority(record); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkRecordKind(record, kRawRunReceiptRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkSchema(repositoryRoot, instancePath); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationAgreement(record, mediaType); !status) {
        return std::unexpected(status.error());
    }
    return summarizeRawRunReceipt(record);
}

std::string buildCanonicalizeOutput(const Descriptor& descriptor, const RawRunReceiptSummary& summary) {
    auto members = summaryMembers(descriptor, summary);
    members.emplace_back("operation", CanonicalValue::makeString("canonicalize"));
    return emitObject(std::move(members));
}

std::string buildValidateOutput(const Descriptor& descriptor, const RawRunReceiptSummary& summary) {
    auto members = summaryMembers(descriptor, summary);
    members.emplace_back("operation", CanonicalValue::makeString("validate"));
    return emitObject(std::move(members));
}

std::string buildRejectionOutput(const RecordFailure& failure) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("ok", CanonicalValue::makeBoolean(false));
    members.emplace_back("rejection", CanonicalValue::makeString(recordRejectionName(failure.rejection)));
    members.emplace_back("detail", CanonicalValue::makeString(failure.detail));
    return emitObject(std::move(members));
}

} // namespace rawframe::tool::evidence
