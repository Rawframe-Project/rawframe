#pragma once

#include "canonical_json.h"
#include "metric_registry.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kEvaluationPolicySchemaPath = "schemas/evaluation-policy-v1.schema.json";
inline constexpr std::string_view kEvaluationPolicyRecordKind = "evaluation_policy";
inline constexpr std::int64_t kEvaluationPolicyGeneration = 1;

inline constexpr std::size_t kMaximumPolicyEntries = 256;

// The only tier this generation admits. Tier 0 is correctness, completeness,
// schema, and harness feedback; every higher tier needs compatible evidence
// from a qualified cell, which does not exist at this gate.
inline constexpr std::string_view kTier0 = "tier_0";

enum class CheckClass : std::uint8_t {
    Completeness,
    Correctness
};

enum class Comparison : std::uint8_t {
    AtMost,
    AtLeast
};

struct PolicyEntry {
    std::string policyKey;
    CheckClass checkClass = CheckClass::Correctness;
    std::string metricId;
    std::int64_t metricGeneration = 0;
    Comparison comparison = Comparison::AtMost;
    std::int64_t boundValue = 0;
    std::int64_t boundScaleExponent = 0;
};

struct EvaluationPolicy {
    std::int64_t policyGeneration = 0;
    std::int64_t metricRegistryGeneration = 0;
    std::string tier;
    std::vector<PolicyEntry> entries;
};

// One entry resolved against the registry it was written for. The bound is
// carried at whichever scale the metric's declared direction leaves it at, and
// that scale is stated rather than assumed, because a value without its scale
// is the shape of every quietly moved threshold. Holding both halves lets a
// caller act on the pair without looking either of them up a second time.
struct BoundPolicyEntry {
    const PolicyEntry* entry = nullptr;
    const MetricEntry* metric = nullptr;
    std::int64_t boundValue = 0;
    std::int64_t boundScaleExponent = 0;
};

// Reads a policy out of already-canonical bytes and gates it as a record. The
// tier, the closed check classes, and the absence of a relative comparison are
// the schema's work; this restates them because a schema widened by accident
// would otherwise widen the loader with it.
[[nodiscard]] RecordResult<EvaluationPolicy> parseEvaluationPolicy(const std::filesystem::path& repositoryRoot,
                                                                   const std::filesystem::path& instancePath,
                                                                   const CanonicalValue& record);

// Resolves every entry against the registry generation the policy names. An
// entry binding an undeclared metric, a metric at another generation, a
// diagnostic metric, a budget class no Tier-0 check may attach to, or a bound
// that cannot reach the metric's scale exactly fails the whole binding.
//
// It resolves and refuses; it never compares an observation or reaches a
// verdict. That belongs to an evaluator, and no evaluator exists yet.
[[nodiscard]] RecordResult<std::vector<BoundPolicyEntry>> bindPolicyToRegistry(const EvaluationPolicy& policy,
                                                                               const MetricRegistry& registry);

} // namespace rawframe::tool::evidence
