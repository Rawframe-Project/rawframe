#include "metric_registry.h"

#include "descriptor.h"
#include "record_gate.h"

#include <algorithm>
#include <set>
#include <string>
#include <utility>

namespace rawframe::tool::evidence {

namespace {

RecordFailure invalid(std::string detail) {
    return RecordFailure{RecordRejection::SchemaInvalid, std::move(detail)};
}

RecordFailure exceeded(std::string detail) {
    return RecordFailure{RecordRejection::LimitExceeded, std::move(detail)};
}

// Every closed vocabulary is parsed by an explicit mapping rather than by
// storing the text. The schema already refuses an unknown spelling, so this is
// the second of the two checks: widening the schema by accident cannot quietly
// admit a value no code here handles.
RecordResult<MetricStability> readStability(const CanonicalValue& entry) {
    auto text = readRequiredText(entry, "stability");
    if (!text) {
        return std::unexpected(text.error());
    }
    if (*text == "stable") {
        return MetricStability::Stable;
    }
    if (*text == "diagnostic") {
        return MetricStability::Diagnostic;
    }
    return std::unexpected(invalid("metric declares an unknown stability: " + *text));
}

RecordResult<MetricPolarity> readPolarity(const CanonicalValue& entry) {
    auto text = readRequiredText(entry, "polarity");
    if (!text) {
        return std::unexpected(text.error());
    }
    if (*text == "lower_is_better") {
        return MetricPolarity::LowerIsBetter;
    }
    if (*text == "higher_is_better") {
        return MetricPolarity::HigherIsBetter;
    }
    return std::unexpected(invalid("metric declares an unknown polarity: " + *text));
}

RecordResult<RescalingRule> readRescaling(const CanonicalValue& entry) {
    const auto* kRescaling = entry.find("rescaling");
    if (kRescaling == nullptr || kRescaling->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("metric declares no rescaling rule"));
    }
    auto direction = readRequiredText(*kRescaling, "direction");
    if (!direction) {
        return std::unexpected(direction.error());
    }
    auto rounding = readRequiredText(*kRescaling, "rounding");
    if (!rounding) {
        return std::unexpected(rounding.error());
    }

    RescalingRule rule;
    if (*direction == "bound_to_observation") {
        rule.direction = RescaleDirection::BoundToObservation;
    } else if (*direction == "observation_to_bound") {
        rule.direction = RescaleDirection::ObservationToBound;
    } else {
        return std::unexpected(invalid("metric declares an unknown rescaling direction: " + *direction));
    }

    if (*rounding == "reject_inexact") {
        rule.rounding = RescaleRounding::RejectInexact;
    } else if (*rounding == "toward_negative_infinity") {
        rule.rounding = RescaleRounding::TowardNegativeInfinity;
    } else if (*rounding == "toward_positive_infinity") {
        rule.rounding = RescaleRounding::TowardPositiveInfinity;
    } else {
        return std::unexpected(invalid("metric declares an unknown rescaling rounding: " + *rounding));
    }
    return rule;
}

RecordResult<std::vector<std::string>> readLabels(const CanonicalValue& entry) {
    std::vector<std::string> labels;
    const auto* kLabels = entry.find("labels");
    if (kLabels == nullptr) {
        return labels;
    }
    if (kLabels->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(invalid("metric labels must be an array"));
    }
    if (kLabels->elements().size() > kMaximumMetricLabels) {
        return std::unexpected(exceeded("metric declares more than 64 labels"));
    }
    std::set<std::string, std::less<>> seen;
    for (const auto& label : kLabels->elements()) {
        if (label.kind() != CanonicalValue::Kind::String) {
            return std::unexpected(invalid("metric labels must be strings"));
        }
        if (!seen.insert(label.text()).second) {
            return std::unexpected(invalid("metric repeats the label " + label.text()));
        }
        labels.push_back(label.text());
    }
    return labels;
}

RecordStatus checkScale(std::int64_t scaleExponent, std::string_view subject) {
    if (scaleExponent < kMinimumScaleExponent || scaleExponent > kMaximumScaleExponent) {
        return std::unexpected(
            exceeded(std::string(subject) + " declares a scale exponent outside the accepted range"));
    }
    return {};
}

RecordResult<MetricEntry> readMetric(const CanonicalValue& entry) {
    if (entry.kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("a registry entry is not an object"));
    }

    MetricEntry metric;
    auto metricId = readRequiredText(entry, "metricId");
    if (!metricId) {
        return std::unexpected(metricId.error());
    }
    metric.metricId = std::move(*metricId);

    auto generation = readRequiredInteger(entry, "metricGeneration");
    if (!generation) {
        return std::unexpected(generation.error());
    }
    if (*generation < 1) {
        return std::unexpected(invalid("metric " + metric.metricId + " declares a generation below one"));
    }
    metric.metricGeneration = *generation;

    auto stability = readStability(entry);
    if (!stability) {
        return std::unexpected(stability.error());
    }
    metric.stability = *stability;

    for (const auto& [member, target] : {
             std::pair<std::string_view, std::string*>{"owner", &metric.owner},
             std::pair<std::string_view, std::string*>{"scope", &metric.scope},
             std::pair<std::string_view, std::string*>{"unit", &metric.unit},
             std::pair<std::string_view, std::string*>{"statistic", &metric.statistic},
             std::pair<std::string_view, std::string*>{"budgetClass", &metric.budgetClass},
             std::pair<std::string_view, std::string*>{"queryId", &metric.queryId},
         }) {
        auto text = readRequiredText(entry, member);
        if (!text) {
            return std::unexpected(text.error());
        }
        *target = std::move(*text);
    }

    auto scaleExponent = readRequiredInteger(entry, "scaleExponent");
    if (!scaleExponent) {
        return std::unexpected(scaleExponent.error());
    }
    if (auto status = checkScale(*scaleExponent, "metric " + metric.metricId); !status) {
        return std::unexpected(status.error());
    }
    metric.scaleExponent = *scaleExponent;

    auto polarity = readPolarity(entry);
    if (!polarity) {
        return std::unexpected(polarity.error());
    }
    metric.polarity = *polarity;

    const auto* kSampling = entry.find("sampling");
    if (kSampling == nullptr || kSampling->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("metric " + metric.metricId + " declares no sampling"));
    }
    auto samplingKind = readRequiredText(*kSampling, "kind");
    if (!samplingKind) {
        return std::unexpected(samplingKind.error());
    }
    metric.samplingKind = std::move(*samplingKind);
    auto blockLength = readRequiredInteger(*kSampling, "blockLength");
    if (!blockLength) {
        return std::unexpected(blockLength.error());
    }
    if (*blockLength < 1) {
        return std::unexpected(invalid("metric " + metric.metricId + " declares a block length below one"));
    }
    metric.blockLength = *blockLength;

    auto rescaling = readRescaling(entry);
    if (!rescaling) {
        return std::unexpected(rescaling.error());
    }
    metric.rescaling = *rescaling;

    auto labels = readLabels(entry);
    if (!labels) {
        return std::unexpected(labels.error());
    }
    metric.labels = std::move(*labels);
    return metric;
}

} // namespace

RecordResult<std::string> readRequiredText(const CanonicalValue& object, std::string_view name) {
    const auto* kMember = object.find(name);
    if (kMember == nullptr || kMember->kind() != CanonicalValue::Kind::String) {
        return std::unexpected(invalid("record carries no string member named " + std::string(name)));
    }
    return kMember->text();
}

RecordResult<std::int64_t> readRequiredInteger(const CanonicalValue& object, std::string_view name) {
    const auto* kMember = object.find(name);
    if (kMember == nullptr || kMember->kind() != CanonicalValue::Kind::Integer) {
        return std::unexpected(invalid("record carries no integer member named " + std::string(name)));
    }
    if (kMember->integer() > kMaximumSafeInteger || kMember->integer() < -kMaximumSafeInteger) {
        return std::unexpected(exceeded(std::string(name) + " lies outside the safe integer range"));
    }
    return kMember->integer();
}

const MetricEntry* MetricRegistry::find(std::string_view metricId, std::int64_t metricGeneration) const {
    const auto kMatch = std::ranges::find_if(metrics, [metricId, metricGeneration](const MetricEntry& entry) {
        return entry.metricId == metricId && entry.metricGeneration == metricGeneration;
    });
    return kMatch == metrics.end() ? nullptr : &*kMatch;
}

RecordResult<MetricRegistry> parseMetricRegistry(const std::filesystem::path& repositoryRoot,
                                                 const std::filesystem::path& instancePath,
                                                 const CanonicalValue& record) {
    if (auto status = checkProducerAuthority(record); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkRecordKind(record, kMetricRegistryRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(repositoryRoot, kMetricRegistrySchemaPath, instancePath); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationMatches(record, kMetricRegistryMediaType, kMetricRegistryGeneration); !status) {
        return std::unexpected(status.error());
    }

    MetricRegistry registry;
    auto generation = readRequiredInteger(record, "registryGeneration");
    if (!generation) {
        return std::unexpected(generation.error());
    }
    if (*generation < 1) {
        return std::unexpected(invalid("registry declares a generation below one"));
    }
    registry.registryGeneration = *generation;

    const auto* kMetrics = record.find("metrics");
    if (kMetrics == nullptr || kMetrics->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(invalid("registry declares no metrics array"));
    }
    if (kMetrics->elements().size() > kMaximumRegisteredMetrics) {
        return std::unexpected(exceeded("registry declares more than 1024 metrics"));
    }

    // Identity is the pair, so this refuses a repeated pair and admits the same
    // identifier at a second generation. A registry that silently kept both
    // halves of a repeated pair would hand every later lookup a coin flip.
    std::set<std::pair<std::string, std::int64_t>, std::less<>> seen;
    registry.metrics.reserve(kMetrics->elements().size());
    for (const auto& element : kMetrics->elements()) {
        auto metric = readMetric(element);
        if (!metric) {
            return std::unexpected(metric.error());
        }
        if (!seen.emplace(metric->metricId, metric->metricGeneration).second) {
            return std::unexpected(invalid("registry declares " + metric->metricId + " twice at one generation"));
        }
        registry.metrics.push_back(std::move(*metric));
    }
    return registry;
}

RecordResult<std::int64_t>
rescaleExact(std::int64_t value, std::int64_t fromExponent, std::int64_t toExponent, RescaleRounding rounding) {
    if (auto status = checkScale(fromExponent, "a value"); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkScale(toExponent, "a value"); !status) {
        return std::unexpected(status.error());
    }
    if (value > kMaximumSafeInteger || value < -kMaximumSafeInteger) {
        return std::unexpected(exceeded("a value outside the safe integer range cannot be rescaled"));
    }

    // Moving to a finer scale multiplies. It is always exact and can leave the
    // representable range, which is a refusal rather than a wrap.
    std::int64_t result = value;
    for (std::int64_t step = toExponent; step < fromExponent; ++step) {
        if (result > kMaximumSafeInteger / 10 || result < -kMaximumSafeInteger / 10) {
            return std::unexpected(exceeded("rescaling leaves the safe integer range"));
        }
        result *= 10;
    }

    // Moving to a coarser scale divides, and division is where a threshold can
    // move. Repeating the single-digit step is the same result as one division
    // for all three rules, and it keeps the remainder visible at every step.
    for (std::int64_t step = fromExponent; step < toExponent; ++step) {
        const std::int64_t kRemainder = result % 10;
        result /= 10;
        if (kRemainder == 0) {
            continue;
        }
        switch (rounding) {
        case RescaleRounding::RejectInexact:
            return std::unexpected(invalid("rescaling is not exact and the metric refuses an inexact bound"));
        case RescaleRounding::TowardNegativeInfinity:
            if (kRemainder < 0) {
                --result;
            }
            break;
        case RescaleRounding::TowardPositiveInfinity:
            if (kRemainder > 0) {
                ++result;
            }
            break;
        }
    }
    return result;
}

} // namespace rawframe::tool::evidence
