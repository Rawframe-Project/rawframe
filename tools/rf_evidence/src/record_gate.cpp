#include "record_gate.h"

#include "schema_oracle.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

std::unexpected<RecordFailure> reject(RecordRejection rejection, std::string detail) {
    return std::unexpected(RecordFailure{rejection, std::move(detail)});
}

// A raw producer reports what happened. These words are how a record would
// start reporting whether that was acceptable, which is the evaluator's
// authority and not any producer record's.
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
                          "an evidence record may not carry a verdict member: " + kMember.first);
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

} // namespace

RecordStatus checkProducerAuthority(const CanonicalValue& record) {
    return walkMemberNames(record);
}

RecordResult<std::string> readRecordKind(const CanonicalValue& record) {
    const auto* kKind = record.find("recordKind");
    if (kKind == nullptr || kKind->kind() != CanonicalValue::Kind::String) {
        return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "record carries no recordKind"});
    }
    return kKind->text();
}

RecordStatus checkRecordKind(const CanonicalValue& record, std::string_view expectedKind) {
    auto declared = readRecordKind(record);
    if (!declared) {
        return std::unexpected(declared.error());
    }
    if (*declared != expectedKind) {
        return reject(RecordRejection::DescriptorMismatch,
                      "record declares kind " + *declared + " where " + std::string(expectedKind) + " was required");
    }
    return {};
}

RecordStatus
checkGenerationMatches(const CanonicalValue& record, std::string_view mediaType, std::int64_t expectedGeneration) {
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
    if (kVersion->integer() != expectedGeneration) {
        return reject(RecordRejection::SchemaInvalid, "record is not a generation 1 evidence record");
    }
    return {};
}

RecordStatus validateAgainstSchema(const std::filesystem::path& repositoryRoot,
                                   std::string_view schemaRelativePath,
                                   const std::filesystem::path& instancePath) {
    const std::array<std::filesystem::path, 1> kImports{repositoryRoot / kEvidenceCommonSchemaPath};
    auto shape = validateJsonShape(repositoryRoot, repositoryRoot / schemaRelativePath, instancePath, kImports);
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

} // namespace rawframe::tool::evidence
