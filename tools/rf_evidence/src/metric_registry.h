#pragma once

#include "canonical_json.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

inline constexpr std::string_view kMetricRegistrySchemaPath = "schemas/metric-registry-v1.schema.json";
inline constexpr std::string_view kMetricRegistryRecordKind = "metric_registry";
inline constexpr std::int64_t kMetricRegistryGeneration = 1;

// The accepted TASK-0005 limits. Each fails closed and none yields a partial
// registry: a caller either holds every entry the file declares or holds none.
inline constexpr std::size_t kMaximumRegisteredMetrics = 1'024;
inline constexpr std::size_t kMaximumMetricLabels = 64;
inline constexpr std::int64_t kMinimumScaleExponent = -18;
inline constexpr std::int64_t kMaximumScaleExponent = 18;

// SPEC-0017's integer subset boundary, restated here because rescaling has to
// prove a result stays inside it and the parser has to prove an input does.
inline constexpr std::int64_t kMaximumSafeInteger = 9'007'199'254'740'991;

// Required-member readers for a canonical record. They are generic rather than
// registry-specific, so record_gate is their eventual home; this Task's write
// envelope does not include that file, and inventing a second copy in the
// policy would have been worse than one honest placement with a stated move.
[[nodiscard]] RecordResult<std::string> readRequiredText(const CanonicalValue& object, std::string_view name);
[[nodiscard]] RecordResult<std::int64_t> readRequiredInteger(const CanonicalValue& object, std::string_view name);

enum class MetricStability : std::uint8_t {
    Stable,
    Diagnostic
};

enum class MetricPolarity : std::uint8_t {
    LowerIsBetter,
    HigherIsBetter
};

// Which side of a comparison moves when a bound and an observation are recorded
// at different scales, and what happens when moving it cannot be exact.
enum class RescaleDirection : std::uint8_t {
    BoundToObservation,
    ObservationToBound
};

enum class RescaleRounding : std::uint8_t {
    RejectInexact,
    TowardNegativeInfinity,
    TowardPositiveInfinity
};

struct RescalingRule {
    RescaleDirection direction = RescaleDirection::BoundToObservation;
    RescaleRounding rounding = RescaleRounding::RejectInexact;

    [[nodiscard]] bool operator==(const RescalingRule&) const = default;
};

// One metric's declared meaning. Every member here says what a quantity is; not
// one of them says whether any value of it is acceptable.
struct MetricEntry {
    std::string metricId;
    std::int64_t metricGeneration = 0;
    MetricStability stability = MetricStability::Diagnostic;
    std::string owner;
    std::string scope;
    std::string unit;
    std::string statistic;
    std::int64_t scaleExponent = 0;
    MetricPolarity polarity = MetricPolarity::LowerIsBetter;
    std::string budgetClass;
    std::string samplingKind;
    std::int64_t blockLength = 0;
    RescalingRule rescaling;
    std::string queryId;
    std::vector<std::string> labels;
};

struct MetricRegistry {
    std::int64_t registryGeneration = 0;
    std::vector<MetricEntry> metrics;

    // Nullptr when the pair is not declared. Identity is the pair, so a lookup
    // by identifier alone does not exist: it would silently resolve a bound
    // written against one definition onto a later, different one.
    [[nodiscard]] const MetricEntry* find(std::string_view metricId, std::int64_t metricGeneration) const;
};

// Reads a registry out of already-canonical bytes and gates it as a record:
// producer authority, kind, schema, generation, then the semantic checks the
// schema cannot express, which are duplicate identity and the declared limits.
[[nodiscard]] RecordResult<MetricRegistry> parseMetricRegistry(const std::filesystem::path& repositoryRoot,
                                                               const std::filesystem::path& instancePath,
                                                               const CanonicalValue& record);

// Moves an integer from one scale to another under a stated rounding rule.
// Widening is exact or it exceeds the safe integer range; narrowing is exact,
// refused, or rounded in the declared direction. Nothing here picks a direction
// on the caller's behalf, because that choice is what moves a threshold.
[[nodiscard]] RecordResult<std::int64_t>
rescaleExact(std::int64_t value, std::int64_t fromExponent, std::int64_t toExponent, RescaleRounding rounding);

} // namespace rawframe::tool::evidence
