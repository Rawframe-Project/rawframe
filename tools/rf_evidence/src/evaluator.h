#pragma once

#include "blob_store.h"
#include "canonical_json.h"
#include "descriptor.h"
#include "evaluation_policy.h"
#include "metric_registry.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kEvaluationReceiptSchemaPath = "schemas/evaluation-receipt-v1.schema.json";
inline constexpr std::string_view kEvaluationReceiptRecordKind = "evaluation_receipt";
inline constexpr std::int64_t kEvaluationReceiptGeneration = 1;

// Which evaluator produced a receipt. SPEC-0014 requires evaluator identity in
// the compatibility key, and it cannot live in a producer record because a
// producer cannot know which evaluator will read it. It is bumped when the
// decision procedure changes, not when the code is edited: two evaluators that
// reach the same verdict from the same inputs are the same evaluator.
inline constexpr std::int64_t kEvaluatorGeneration = 1;

// The accepted TASK-0006 limits. Each matches the bound the record it reads
// already carries, because a reader that admitted more than a producer can
// write would be enforcing nothing.
inline constexpr std::size_t kMaximumObservedMetrics = 4096;
inline constexpr std::size_t kMaximumEvaluatedChecks = kMaximumPolicyEntries;

// SPEC-0014's order, restricted to what Tier 0 can reach. Absolute objectives,
// anchor regression, rolling-main regression, and tier stability are absent
// because a Tier-0 policy cannot bind a metric they would apply to.
enum class CheckPhase : std::uint8_t {
    Completeness,
    Correctness,
    HardCeiling
};

enum class CheckOutcome : std::uint8_t {
    Passed,
    Failed,
    NotRun
};

// Why a check failed or did not run, from a closed vocabulary. A record that
// gates on free text is a record whose meaning changes with its wording.
enum class CheckReason : std::uint8_t {
    None,
    BoundViolated,
    ObservationMissing,
    EarlierPhaseFailed
};

// Everything the evaluator was handed, with each input's identity beside it.
// The paths are how the inputs were found; the descriptors are what was
// actually read, and only the second survives into the receipt.
struct EvaluationInputs {
    std::filesystem::path repositoryRoot;
    std::filesystem::path evidenceSetPath;
    Descriptor evidenceSetDescriptor;
    Descriptor metricRegistryDescriptor;
    Descriptor evaluationPolicyDescriptor;
};

// Reads an Evidence Set, retrieves every eligible attempt's receipt from the
// store, resolves the policy against the registry, and emits one
// EvaluationReceipt.
//
// It reads and decides. It writes nothing, repairs nothing, normalizes nothing,
// and leaves every input byte-identical to how it found it.
//
// Two outcomes are spelled differently on purpose. A failure returned here
// means nothing could be evaluated: an input was invalid, incomplete, corrupt,
// incompatible, or unsupported, and no receipt exists. A receipt whose verdict
// is `failed` means the evaluation completed and the evidence did not pass.
// Collapsing the two would let a broken input read as a clean negative result.
//
// Checks run in phase order. The first phase that produces a failure stops the
// later phases, whose checks are retained with outcome `not_run`, so a later
// pass can never appear to rescue an earlier blocking failure and a reader can
// always see which checks nobody reached.
[[nodiscard]] RecordResult<CanonicalValue> evaluateEvidenceSet(const BlobStore& store,
                                                               const EvaluationInputs& inputs,
                                                               const CanonicalValue& evidenceSet,
                                                               const MetricRegistry& registry,
                                                               const EvaluationPolicy& policy,
                                                               std::string_view evaluationId);

} // namespace rawframe::tool::evidence
