#pragma once

#include "blob_store.h"
#include "canonical_json.h"
#include "descriptor.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kAttemptPlanSchemaPath = "schemas/attempt-plan-v1.schema.json";
inline constexpr std::string_view kAttemptPlanRecordKind = "attempt_plan";
inline constexpr std::int64_t kAttemptPlanGeneration = 1;

inline constexpr std::string_view kEvidenceSetSchemaPath = "schemas/evidence-set-v1.schema.json";
inline constexpr std::string_view kEvidenceSetRecordKind = "evidence_set";
inline constexpr std::int64_t kEvidenceSetGeneration = 1;

// The ledger's finite limits, fixed by the accepted TASK-0004 packet. Each
// fails closed and none of them yields a partial set.
inline constexpr std::size_t kMaximumPlannedAttempts = 4096;
inline constexpr std::size_t kMaximumSupersedesDepth = 64;

// The status recorded for an attempt that produced no receipt at all. It is a
// value rather than an absence, because an assembler that represented "no
// receipt" by leaving the member out would produce a ledger in which a missing
// attempt and an unasked question look the same.
inline constexpr std::string_view kNoReceiptStatus = "no_receipt";

// One scheduled attempt as the plan declares it.
struct PlannedAttempt {
    std::string attemptId;
    std::int64_t attemptOrdinal = 0;
    std::int64_t repetitionOrdinal = 0;
    std::string supersedesAttemptId;
    bool hasReceipt = false;
    Descriptor receipt;
};

struct AttemptPlan {
    std::string planId;
    std::string tier;
    std::int64_t repetitionCount = 0;
    std::int64_t attemptCount = 0;
    std::vector<PlannedAttempt> attempts;
};

// The compatibility facts a receipt states. Assembly copies them and compares
// them; it never fills one in, prefers one, or reconciles two.
struct CompatibilityFacts {
    std::string profileId;
    std::string workloadFingerprint;
    std::string targetId;
    std::string platformId;
    std::string configuration;
    std::string closureFingerprint;
    std::string harnessId;
    std::int64_t metricRegistryGeneration = 0;
    std::int64_t runnerGeneration = 0;
    std::string cellFingerprint;

    [[nodiscard]] bool operator==(const CompatibilityFacts&) const = default;
};

// Reads a plan out of already-canonical bytes and gates it as a record.
[[nodiscard]] RecordResult<AttemptPlan> parseAttemptPlan(const std::filesystem::path& repositoryRoot,
                                                         const std::filesystem::path& instancePath,
                                                         const CanonicalValue& record);

// Reads the compatibility facts and terminal status a receipt states. It does
// not validate the receipt: that is the receipt's own gate, run before this.
[[nodiscard]] RecordResult<CompatibilityFacts> readCompatibility(const CanonicalValue& receipt);
[[nodiscard]] RecordResult<std::string> readTerminalStatus(const CanonicalValue& receipt);

// Assembles the ledger. Every planned attempt is accounted for exactly once, in
// declared ordinal order, and any gap, duplicate, unplanned member, broken
// supersedes chain, or compatibility disagreement fails the whole assembly. It
// never emits a partial set.
//
// The store supplies receipt bytes by digest. Nothing is enumerated: the plan
// is the only statement of what should exist, which is what makes an omission
// detectable at all.
[[nodiscard]] RecordResult<CanonicalValue>
assembleEvidenceSet(const BlobStore& store, const AttemptPlan& plan, std::string_view evidenceSetId);

// The command-line summary of an assembled or validated set. It is the same
// shape the receipt emits, because a caller that has to branch on record kind
// to read a result would be reading two output contracts rather than one.
[[nodiscard]] std::string
buildEvidenceSetOutput(const Descriptor& descriptor, const CanonicalValue& record, std::string_view operation);

} // namespace rawframe::tool::evidence
