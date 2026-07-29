#pragma once

#include "canonical_json.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kBaselineRecordSchemaPath = "schemas/baseline-record-v1.schema.json";
inline constexpr std::string_view kBaselineRecordRecordKind = "baseline_record";
inline constexpr std::int64_t kBaselineRecordGeneration = 1;

inline constexpr std::size_t kMaximumAffectedMetrics = 64;
inline constexpr std::size_t kMaximumPredecessorChain = 32;

// Why a record shaped like a promotion is not one.
//
// Separate from RecordRejection because these are not statements about bytes.
// A record can be perfectly canonical, satisfy the schema in every particular,
// and still describe a promotion that must not happen; conflating the two would
// make "these bytes are malformed" and "this promotion approves itself" the
// same answer to a reader deciding what to do next.
//
// Every member is decidable from the record's own bytes. A check that needed
// repository state would be a check whose result depends on where the record
// was read, and a promotion defect must not be curable by moving the file.
enum class BaselineDefect : std::uint8_t {
    // The promotion rides in on the change it approves.
    SelfUpdate,
    // The candidate's own evaluation stands in for the protected review.
    SelfPromotion,
    // Neither a first-baseline marker nor a predecessor, so the chain is a gap.
    MissingPredecessor,
    // A status that changed by edit rather than by a successor naming it.
    MutableRole,
    // A dimension the tier cannot support, or a margin against an unnamed metric.
    IncompatibleScope,
    // A promotion pointing at nothing, or at one artifact twice.
    MissingEvidence,
    // The review reference is the candidate's own output.
    CandidateControlledPolicy,
    // Provenance pointing somewhere this tool cannot verify offline.
    UnsupportedProvenance,
    // Local Tier-0 evidence, which SPEC-0014 never admits for promotion. Every
    // record this tool can read carries this one, because the shared schema
    // pins provenance to diagnostic_untrusted. It is the general case and not
    // an edge: there is no record here that could be promoted.
    InsufficientTrust,
};

[[nodiscard]] constexpr const char* baselineDefectName(BaselineDefect defect) noexcept {
    switch (defect) {
    case BaselineDefect::SelfUpdate:
        return "self_update";
    case BaselineDefect::SelfPromotion:
        return "self_promotion";
    case BaselineDefect::MissingPredecessor:
        return "missing_predecessor";
    case BaselineDefect::MutableRole:
        return "mutable_role";
    case BaselineDefect::IncompatibleScope:
        return "incompatible_scope";
    case BaselineDefect::MissingEvidence:
        return "missing_evidence";
    case BaselineDefect::CandidateControlledPolicy:
        return "candidate_controlled_policy";
    case BaselineDefect::UnsupportedProvenance:
        return "unsupported_provenance";
    case BaselineDefect::InsufficientTrust:
        return "insufficient_trust";
    }
    return "unknown_defect";
}

enum class BaselineRole : std::uint8_t {
    Anchor,
    RollingMain
};

enum class BaselineState : std::uint8_t {
    Active,
    Superseded,
    Revoked
};

// A validated view of a record that satisfied the schema and carried no
// promotion defect. It holds what a reader needs to talk about the record and
// deliberately holds no promotion state: there is no member here a caller could
// set to make this baseline effective, because no such transition exists in
// this generation and a field reserved for one would be a future flag.
struct BaselineRecord {
    std::string baselineId;
    BaselineRole role = BaselineRole::Anchor;
    std::string profileId;
    std::string evaluationReceiptDigest;
    std::string evidenceSetDigest;
    bool firstBaseline = false;
    std::string predecessorDigest;
    std::vector<std::string> affectedMetrics;
    BaselineState state = BaselineState::Active;
    std::string approvingProjectOwner;
    std::string approvalTimestamp;
};

// Reads a baseline record out of already-canonical bytes and gates it.
//
// Success means the bytes are a well-formed BaselineRecord that describes no
// promotion this specification forbids. It does not mean a baseline exists, is
// active, is trusted, or has been promoted, and nothing in this tool turns it
// into any of those. There is no writer, no promoter, no activator, and no
// verb that reaches one.
[[nodiscard]] RecordResult<BaselineRecord> parseBaselineRecord(const std::filesystem::path& repositoryRoot,
                                                               const std::filesystem::path& instancePath,
                                                               const CanonicalValue& record);

// Why this record could never be promoted, whatever else is true of it.
//
// Always InsufficientTrust. This is a function rather than a constant so the
// reason travels with the record and appears in a caller's output, and it
// returns one value because there is one: local Tier-0 evidence is not
// promotable, and a second return value would be the beginning of a path that
// is. A test asserts it admits exactly one.
[[nodiscard]] BaselineDefect promotionRefusal(const BaselineRecord& record) noexcept;

} // namespace rawframe::tool::evidence
