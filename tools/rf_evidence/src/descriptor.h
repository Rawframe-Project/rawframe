#pragma once

#include "canonical_json.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

// The generation-1 evidence media type grammar:
//   application/vnd.rawframe.evidence.<kind>.v<generation>+json
inline constexpr std::string_view kRawRunReceiptMediaType = "application/vnd.rawframe.evidence.raw-run-receipt.v1+json";
inline constexpr std::string_view kAttemptPlanMediaType = "application/vnd.rawframe.evidence.attempt-plan.v1+json";
inline constexpr std::string_view kEvidenceSetMediaType = "application/vnd.rawframe.evidence.evidence-set.v1+json";

// The maintained authorities. They are read material rather than produced
// evidence, but they are records under the same canonical contract and carry
// their identity outside themselves for the same reason: bytes that describe
// themselves cannot be checked against anything.
inline constexpr std::string_view kEvidenceIndexMediaType = "application/vnd.rawframe.evidence.evidence-index.v1+json";
inline constexpr std::string_view kMetricRegistryMediaType =
    "application/vnd.rawframe.evidence.metric-registry.v1+json";
inline constexpr std::string_view kEvaluationPolicyMediaType =
    "application/vnd.rawframe.evidence.evaluation-policy.v1+json";

// External content identity. It describes bytes and is never inside them, so a
// descriptor and the record it identifies are always two separate documents.
struct Descriptor {
    std::string mediaType;
    std::uint64_t byteLength = 0;
    std::string digest;
};

// Builds the descriptor for content that was just produced.
[[nodiscard]] RecordResult<Descriptor> describeBytes(std::string_view bytes, std::string_view mediaType);

// Reads a descriptor out of an already-parsed canonical value. Shape errors are
// descriptor mismatches rather than schema failures, because a caller reaches
// this before any record semantics exist.
[[nodiscard]] RecordResult<Descriptor> parseDescriptor(const CanonicalValue& value);

// Proves a descriptor identifies exactly these bytes: media type, then length,
// then digest, in that order and all three before any semantic use.
[[nodiscard]] RecordStatus
verifyDescriptor(const Descriptor& descriptor, std::string_view bytes, std::string_view expectedMediaType);

[[nodiscard]] CanonicalValue describeAsValue(const Descriptor& descriptor);

} // namespace rawframe::tool::evidence
