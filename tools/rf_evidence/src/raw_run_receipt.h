#pragma once

#include "canonical_json.h"
#include "descriptor.h"
#include "record_gate.h"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kRawRunReceiptSchemaPath = "schemas/raw-run-receipt-v1.schema.json";
inline constexpr std::string_view kRawRunReceiptRecordKind = "raw_run_receipt";
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

// The receipt's own bindings of the generic gate: this record kind's schema and
// this record kind's generation. They exist so that "check this receipt against
// its schema" has one name and one meaning, distinct from record_gate's "check
// this record against the schema I am handing you".
[[nodiscard]] RecordStatus checkSchema(const std::filesystem::path& repositoryRoot,
                                       const std::filesystem::path& instancePath);
[[nodiscard]] RecordStatus checkGenerationAgreement(const CanonicalValue& record, std::string_view mediaType);

[[nodiscard]] RecordResult<RawRunReceiptSummary> summarizeRawRunReceipt(const CanonicalValue& record);

// The full semantic gate for this record kind, composing record_gate's checks
// in the order SPEC-0017 requires: producer authority, kind, schema, then
// generation agreement.
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
