#pragma once

#include "canonical_json.h"
#include "descriptor.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kRawRunReceiptSchemaPath = "schemas/raw-run-receipt-v1.schema.json";
inline constexpr std::string_view kEvidenceCommonSchemaPath = "schemas/evidence-common-v1.schema.json";
inline constexpr std::int64_t kRawRunReceiptGeneration = 1;

// What a caller learns from a record without being handed a verdict. Every
// field here is an observation restated, and none of them is an outcome.
struct RawRunReceiptSummary {
    std::string runId;
    std::string status;
    std::string provenance;
    std::size_t metricCount = 0;
    std::size_t lifecycleEventCount = 0;
    std::size_t attachmentCount = 0;
};

// No member name anywhere in a record may claim an outcome. The schema already
// closes every object, so this cannot fire against the accepted schema; it
// exists so that widening a schema by accident cannot quietly open the door
// this rule closes.
[[nodiscard]] RecordStatus checkProducerAuthority(const CanonicalValue& record);

// The generation recorded in the bytes and the generation named by the media
// type must agree. Neither is preferred over the other, because a preference
// order is how one of two cross-checks becomes decorative.
[[nodiscard]] RecordStatus checkGenerationAgreement(const CanonicalValue& record, std::string_view mediaType);

// Generic Draft 2020-12 validation through the pinned offline oracle. The
// instance is passed by path because the oracle reads files, and the canonical
// bytes of a record carry the same semantics as the authored bytes they came
// from, so validating either proves the same thing.
[[nodiscard]] RecordStatus checkSchema(const std::filesystem::path& repositoryRoot,
                                       const std::filesystem::path& instancePath);

[[nodiscard]] RecordResult<RawRunReceiptSummary> summarizeRawRunReceipt(const CanonicalValue& record);

// The full semantic gate, in the order SPEC-0017 requires: producer authority,
// then schema, then generation agreement.
[[nodiscard]] RecordResult<RawRunReceiptSummary> validateRawRunReceipt(const std::filesystem::path& repositoryRoot,
                                                                       const std::filesystem::path& instancePath,
                                                                       const CanonicalValue& record,
                                                                       std::string_view mediaType);

// Operation output, emitted through this Task's own canonical serializer
// because it is the component that owns exact JSON.
[[nodiscard]] std::string buildCanonicalizeOutput(const Descriptor& descriptor, const RawRunReceiptSummary& summary);
[[nodiscard]] std::string buildValidateOutput(const Descriptor& descriptor, const RawRunReceiptSummary& summary);
[[nodiscard]] std::string buildRejectionOutput(const RecordFailure& failure);

} // namespace rawframe::tool::evidence
