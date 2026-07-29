#include "evaluation_policy.h"

#include "descriptor.h"
#include "record_gate.h"

#include <algorithm>
#include <array>
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

// The budget classes a Tier-0 completeness or correctness check may attach to.
// A hard ceiling fails deterministically and a contract constant is a stated
// fact, so both mean the same thing on every machine. A performance objective,
// a regression threshold, an overload threshold, a supervisor deadline, and a
// workload parameter do not, and binding one here would let an untrusted local
// run report a verdict on a canonical budget.
constexpr std::array kTier0BudgetClasses{
    std::string_view{"hard_ceiling"},
    std::string_view{"contract_constant"},
};

RecordResult<CheckClass> readCheckClass(const CanonicalValue& entry) {
    auto text = readRequiredText(entry, "checkClass");
    if (!text) {
        return std::unexpected(text.error());
    }
    if (*text == "completeness") {
        return CheckClass::Completeness;
    }
    if (*text == "correctness") {
        return CheckClass::Correctness;
    }
    return std::unexpected(invalid("policy entry declares an unknown check class: " + *text));
}

RecordResult<Comparison> readComparison(const CanonicalValue& entry) {
    auto text = readRequiredText(entry, "comparison");
    if (!text) {
        return std::unexpected(text.error());
    }
    if (*text == "at_most") {
        return Comparison::AtMost;
    }
    if (*text == "at_least") {
        return Comparison::AtLeast;
    }
    return std::unexpected(invalid("policy entry declares an unknown comparison: " + *text));
}

RecordResult<PolicyEntry> readEntry(const CanonicalValue& element) {
    if (element.kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("a policy entry is not an object"));
    }

    PolicyEntry entry;
    auto policyKey = readRequiredText(element, "policyKey");
    if (!policyKey) {
        return std::unexpected(policyKey.error());
    }
    entry.policyKey = std::move(*policyKey);

    auto checkClass = readCheckClass(element);
    if (!checkClass) {
        return std::unexpected(checkClass.error());
    }
    entry.checkClass = *checkClass;

    auto metricId = readRequiredText(element, "metricId");
    if (!metricId) {
        return std::unexpected(metricId.error());
    }
    entry.metricId = std::move(*metricId);

    auto generation = readRequiredInteger(element, "metricGeneration");
    if (!generation) {
        return std::unexpected(generation.error());
    }
    if (*generation < 1) {
        return std::unexpected(invalid("policy entry " + entry.policyKey + " binds a generation below one"));
    }
    entry.metricGeneration = *generation;

    auto comparison = readComparison(element);
    if (!comparison) {
        return std::unexpected(comparison.error());
    }
    entry.comparison = *comparison;

    const auto* kBound = element.find("bound");
    if (kBound == nullptr || kBound->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("policy entry " + entry.policyKey + " declares no bound"));
    }
    auto value = readRequiredInteger(*kBound, "value");
    if (!value) {
        return std::unexpected(value.error());
    }
    entry.boundValue = *value;
    auto scaleExponent = readRequiredInteger(*kBound, "scaleExponent");
    if (!scaleExponent) {
        return std::unexpected(scaleExponent.error());
    }
    if (*scaleExponent < kMinimumScaleExponent || *scaleExponent > kMaximumScaleExponent) {
        return std::unexpected(
            exceeded("policy entry " + entry.policyKey + " declares a scale exponent outside the accepted range"));
    }
    entry.boundScaleExponent = *scaleExponent;
    return entry;
}

} // namespace

RecordResult<EvaluationPolicy> parseEvaluationPolicy(const std::filesystem::path& repositoryRoot,
                                                     const std::filesystem::path& instancePath,
                                                     const CanonicalValue& record) {
    if (auto status = checkProducerAuthority(record); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkRecordKind(record, kEvaluationPolicyRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(repositoryRoot, kEvaluationPolicySchemaPath, instancePath); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationMatches(record, kEvaluationPolicyMediaType, kEvaluationPolicyGeneration);
        !status) {
        return std::unexpected(status.error());
    }

    EvaluationPolicy policy;
    auto tier = readRequiredText(record, "tier");
    if (!tier) {
        return std::unexpected(tier.error());
    }
    if (*tier != kTier0) {
        return std::unexpected(invalid("policy claims tier " + *tier + ", which this gate cannot produce"));
    }
    policy.tier = std::move(*tier);

    const auto* kTrust = record.find("trust");
    if (kTrust == nullptr || kTrust->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("policy declares no trust"));
    }
    auto trust = readRequiredText(*kTrust, "provenance");
    if (!trust) {
        return std::unexpected(trust.error());
    }
    if (*trust != "diagnostic_untrusted") {
        return std::unexpected(invalid("policy claims provenance " + *trust + ", which this gate cannot produce"));
    }

    auto policyGeneration = readRequiredInteger(record, "policyGeneration");
    if (!policyGeneration) {
        return std::unexpected(policyGeneration.error());
    }
    if (*policyGeneration < 1) {
        return std::unexpected(invalid("policy declares a generation below one"));
    }
    policy.policyGeneration = *policyGeneration;

    auto registryGeneration = readRequiredInteger(record, "metricRegistryGeneration");
    if (!registryGeneration) {
        return std::unexpected(registryGeneration.error());
    }
    if (*registryGeneration < 1) {
        return std::unexpected(invalid("policy names a registry generation below one"));
    }
    policy.metricRegistryGeneration = *registryGeneration;

    const auto* kEntries = record.find("entries");
    if (kEntries == nullptr || kEntries->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(invalid("policy declares no entries array"));
    }
    if (kEntries->elements().size() > kMaximumPolicyEntries) {
        return std::unexpected(exceeded("policy declares more than 256 entries"));
    }

    std::set<std::string, std::less<>> keys;
    policy.entries.reserve(kEntries->elements().size());
    for (const auto& element : kEntries->elements()) {
        auto entry = readEntry(element);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        if (!keys.insert(entry->policyKey).second) {
            return std::unexpected(invalid("policy declares the key " + entry->policyKey + " twice"));
        }
        policy.entries.push_back(std::move(*entry));
    }
    return policy;
}

RecordResult<std::vector<BoundPolicyEntry>> bindPolicyToRegistry(const EvaluationPolicy& policy,
                                                                 const MetricRegistry& registry) {
    if (policy.metricRegistryGeneration != registry.registryGeneration) {
        return std::unexpected(invalid("policy is written against another registry generation"));
    }

    std::vector<BoundPolicyEntry> bound;
    bound.reserve(policy.entries.size());
    for (const auto& entry : policy.entries) {
        const MetricEntry* metric = registry.find(entry.metricId, entry.metricGeneration);
        if (metric == nullptr) {
            return std::unexpected(invalid("policy entry " + entry.policyKey + " binds an undeclared metric identity"));
        }
        if (metric->stability != MetricStability::Stable) {
            return std::unexpected(invalid("policy entry " + entry.policyKey + " binds a diagnostic metric"));
        }
        if (std::ranges::find(kTier0BudgetClasses, metric->budgetClass) == kTier0BudgetClasses.end()) {
            return std::unexpected(invalid("policy entry " + entry.policyKey + " binds a " + metric->budgetClass +
                                           ", which a Tier-0 check may not attach to"));
        }

        // The metric owns the direction, so a policy cannot state a bound in
        // whichever direction happens to round its own way. Under
        // bound_to_observation the bound moves now, once, and any inexactness
        // is refused here rather than at every later comparison. Under
        // observation_to_bound the bound stays where it was written and the
        // observation is what will move, so nothing is rescaled at this point.
        if (metric->rescaling.direction == RescaleDirection::ObservationToBound) {
            bound.push_back(BoundPolicyEntry{&entry, metric, entry.boundValue, entry.boundScaleExponent});
            continue;
        }
        auto value =
            rescaleExact(entry.boundValue, entry.boundScaleExponent, metric->scaleExponent, metric->rescaling.rounding);
        if (!value) {
            return std::unexpected(value.error());
        }
        bound.push_back(BoundPolicyEntry{&entry, metric, *value, metric->scaleExponent});
    }
    return bound;
}

} // namespace rawframe::tool::evidence
