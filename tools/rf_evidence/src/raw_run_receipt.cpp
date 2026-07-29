#include "raw_run_receipt.h"

#include "schema_oracle.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

std::unexpected<RecordFailure> reject(RecordRejection rejection, std::string detail) {
    return std::unexpected(RecordFailure{rejection, std::move(detail)});
}

// A raw producer reports what happened. These words are how a record would
// start reporting whether that was acceptable, which is the evaluator's
// authority and not this record's.
constexpr std::array kForbiddenMemberNames{
    std::string_view{"accepted"},
    std::string_view{"baseline"},
    std::string_view{"fail"},
    std::string_view{"failed"},
    std::string_view{"pass"},
    std::string_view{"passed"},
    std::string_view{"promoted"},
    std::string_view{"regressed"},
    std::string_view{"verdict"},
};

RecordStatus walkMemberNames(const CanonicalValue& value) {
    if (value.kind() == CanonicalValue::Kind::Array) {
        for (const auto& kElement : value.elements()) {
            if (auto status = walkMemberNames(kElement); !status) {
                return status;
            }
        }
        return {};
    }
    if (value.kind() != CanonicalValue::Kind::Object) {
        return {};
    }
    for (const auto& kMember : value.members()) {
        if (std::ranges::find(kForbiddenMemberNames, kMember.first) != kForbiddenMemberNames.end()) {
            return reject(RecordRejection::SchemaInvalid,
                          "a raw run receipt may not carry a verdict member: " + kMember.first);
        }
        if (auto status = walkMemberNames(kMember.second); !status) {
            return status;
        }
    }
    return {};
}

// Reads the generation out of `...<kind>.v<generation>+json`.
RecordResult<std::int64_t> mediaTypeGeneration(std::string_view mediaType) {
    constexpr std::string_view kSuffix = "+json";
    if (!mediaType.ends_with(kSuffix)) {
        return std::unexpected(
            RecordFailure{RecordRejection::DescriptorMismatch, "media type does not name a JSON record"});
    }
    auto body = mediaType.substr(0, mediaType.size() - kSuffix.size());
    const auto kMarker = body.rfind(".v");
    if (kMarker == std::string_view::npos) {
        return std::unexpected(
            RecordFailure{RecordRejection::DescriptorMismatch, "media type carries no format generation"});
    }
    const auto kDigits = body.substr(kMarker + 2);
    if (kDigits.empty() || !std::ranges::all_of(kDigits, [](char character) {
            return character >= '0' && character <= '9';
        })) {
        return std::unexpected(
            RecordFailure{RecordRejection::DescriptorMismatch, "media type generation is not a number"});
    }
    std::int64_t generation = 0;
    const auto kResult = std::from_chars(kDigits.data(), kDigits.data() + kDigits.size(), generation);
    if (kResult.ec != std::errc{}) {
        return std::unexpected(
            RecordFailure{RecordRejection::DescriptorMismatch, "media type generation is out of range"});
    }
    return generation;
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

RecordStatus checkProducerAuthority(const CanonicalValue& record) {
    return walkMemberNames(record);
}

RecordStatus checkGenerationAgreement(const CanonicalValue& record, std::string_view mediaType) {
    const auto* kVersion = record.find("schemaVersion");
    if (kVersion == nullptr || kVersion->kind() != CanonicalValue::Kind::Integer) {
        return reject(RecordRejection::SchemaInvalid, "record carries no integer schemaVersion");
    }
    auto declared = mediaTypeGeneration(mediaType);
    if (!declared) {
        return std::unexpected(declared.error());
    }
    if (kVersion->integer() != *declared) {
        return reject(RecordRejection::DescriptorMismatch, "record schemaVersion and media type generation disagree");
    }
    if (kVersion->integer() != kRawRunReceiptGeneration) {
        return reject(RecordRejection::SchemaInvalid, "record is not a generation 1 raw run receipt");
    }
    return {};
}

RecordStatus checkSchema(const std::filesystem::path& repositoryRoot, const std::filesystem::path& instancePath) {
    const std::array<std::filesystem::path, 1> kImports{repositoryRoot / kEvidenceCommonSchemaPath};
    auto shape = validateJsonShape(repositoryRoot, repositoryRoot / kRawRunReceiptSchemaPath, instancePath, kImports);
    if (shape) {
        return {};
    }
    // An oracle that could not run, could not resolve, or answered in a way
    // this tool does not recognise is a failure to validate. It is never a
    // silently skipped validation.
    if (shape.error().code == FailureCode::InvalidManifest) {
        return reject(RecordRejection::SchemaInvalid, "the record does not satisfy its schema");
    }
    return reject(RecordRejection::SchemaInvalid, "schema validation could not be performed: " + shape.error().message);
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
