#include "evaluator.h"

#include "evidence_set.h"
#include "raw_run_receipt.h"
#include "record_gate.h"

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

RecordFailure invalid(std::string detail) {
    return RecordFailure{RecordRejection::SchemaInvalid, std::move(detail)};
}

RecordFailure mismatched(std::string detail) {
    return RecordFailure{RecordRejection::DescriptorMismatch, std::move(detail)};
}

RecordFailure exceeded(std::string detail) {
    return RecordFailure{RecordRejection::LimitExceeded, std::move(detail)};
}

constexpr std::string_view phaseName(CheckPhase phase) noexcept {
    switch (phase) {
    case CheckPhase::Completeness:
        return "completeness";
    case CheckPhase::Correctness:
        return "correctness";
    case CheckPhase::HardCeiling:
        return "hard_ceiling";
    }
    return "correctness";
}

constexpr std::string_view outcomeName(CheckOutcome outcome) noexcept {
    switch (outcome) {
    case CheckOutcome::Passed:
        return "passed";
    case CheckOutcome::Failed:
        return "failed";
    case CheckOutcome::NotRun:
        return "not_run";
    }
    return "not_run";
}

constexpr std::string_view reasonName(CheckReason reason) noexcept {
    switch (reason) {
    case CheckReason::BoundViolated:
        return "bound_violated";
    case CheckReason::ObservationMissing:
        return "observation_missing";
    case CheckReason::EarlierPhaseFailed:
        return "earlier_phase_failed";
    case CheckReason::None:
        return {};
    }
    return {};
}

// A check's phase. The check class decides whether the question is "was this
// observed at all"; among the questions that are not, a hard ceiling is
// evaluated after ordinary correctness because SPEC-0014 orders it that way.
// Nothing here reads a name or a unit to guess a phase.
CheckPhase phaseOf(const BoundPolicyEntry& bound) {
    if (bound.entry->checkClass == CheckClass::Completeness) {
        return CheckPhase::Completeness;
    }
    if (bound.metric->budgetClass == "hard_ceiling") {
        return CheckPhase::HardCeiling;
    }
    return CheckPhase::Correctness;
}

// One observation as a receipt stated it, already proven to agree with the
// registry about what the metric is.
struct Observation {
    std::int64_t value = 0;
    std::int64_t scaleExponent = 0;
};

// One eligible attempt, its receipt's identity, and what that receipt observed.
struct EligibleRun {
    std::string attemptId;
    Descriptor descriptor;
    std::map<std::string, Observation, std::less<>> observations;
};

// The comparison the metric's own rescaling rule declares. Under
// `bound_to_observation` the bound moves to where the observation is, which is
// the direction that keeps a breach visible when the two scales differ. Under
// `observation_to_bound` the observation moves instead. Nothing picks a
// direction on the caller's behalf, and an inexact move under `reject_inexact`
// fails rather than rounding a threshold quietly.
struct ScaledComparison {
    std::int64_t observed = 0;
    std::int64_t bound = 0;
    std::int64_t scaleExponent = 0;
};

RecordResult<ScaledComparison>
compareAt(const BoundPolicyEntry& bound, const Observation& observation, std::string_view attemptId) {
    const RescaleRounding kRounding = bound.metric->rescaling.rounding;
    if (bound.metric->rescaling.direction == RescaleDirection::BoundToObservation) {
        auto moved = rescaleExact(
            bound.entry->boundValue, bound.entry->boundScaleExponent, observation.scaleExponent, kRounding);
        if (!moved) {
            return std::unexpected(moved.error());
        }
        return ScaledComparison{observation.value, *moved, observation.scaleExponent};
    }
    auto moved = rescaleExact(observation.value, observation.scaleExponent, bound.entry->boundScaleExponent, kRounding);
    if (!moved) {
        return std::unexpected(
            RecordFailure{moved.error().rejection, "attempt " + std::string(attemptId) + ": " + moved.error().detail});
    }
    return ScaledComparison{*moved, bound.entry->boundValue, bound.entry->boundScaleExponent};
}

bool satisfies(Comparison comparison, std::int64_t observed, std::int64_t bound) {
    return comparison == Comparison::AtMost ? observed <= bound : observed >= bound;
}

// Reads what one receipt observed, keeping only metrics the registry declares.
// An undeclared metric is diagnostic material under ADR-0019 and is not an
// error; it simply cannot gate anything, so it is not carried forward. A
// declared metric whose stated unit or statistic contradicts the registry is a
// different matter: the receipt and the registry disagree about what was
// measured, and no comparison between them would mean anything.
RecordResult<std::map<std::string, Observation, std::less<>>>
readObservations(const CanonicalValue& receipt, const MetricRegistry& registry, std::string_view attemptId) {
    const auto* kObservations = receipt.find("observations");
    if (kObservations == nullptr || kObservations->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("receipt for attempt " + std::string(attemptId) + " declares no observations"));
    }
    const auto* kMetrics = kObservations->find("metrics");
    if (kMetrics == nullptr || kMetrics->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(
            invalid("receipt for attempt " + std::string(attemptId) + " declares no observed metrics"));
    }
    if (kMetrics->elements().size() > kMaximumObservedMetrics) {
        return std::unexpected(exceeded("receipt for attempt " + std::string(attemptId) +
                                        " observes more metrics than the accepted bound"));
    }

    std::map<std::string, Observation, std::less<>> observations;
    for (const auto& kEntry : kMetrics->elements()) {
        auto metricId = readRequiredText(kEntry, "metricId");
        if (!metricId) {
            return std::unexpected(metricId.error());
        }
        const MetricEntry* declared = nullptr;
        for (const auto& kMetric : registry.metrics) {
            if (kMetric.metricId == *metricId) {
                declared = &kMetric;
                break;
            }
        }
        if (declared == nullptr) {
            continue;
        }

        auto unit = readRequiredText(kEntry, "unit");
        if (!unit) {
            return std::unexpected(unit.error());
        }
        if (*unit != declared->unit) {
            return std::unexpected(mismatched("attempt " + std::string(attemptId) + " reports " + *metricId + " in " +
                                              *unit + " where the registry declares " + declared->unit));
        }
        auto statistic = readRequiredText(kEntry, "statistic");
        if (!statistic) {
            return std::unexpected(statistic.error());
        }
        if (*statistic != declared->statistic) {
            return std::unexpected(mismatched("attempt " + std::string(attemptId) + " reports " + *metricId + " as " +
                                              *statistic + " where the registry declares " + declared->statistic));
        }

        auto value = readRequiredInteger(kEntry, "value");
        if (!value) {
            return std::unexpected(value.error());
        }
        std::int64_t scaleExponent = 0;
        if (const auto* kScale = kEntry.find("scaleExponent"); kScale != nullptr) {
            if (kScale->kind() != CanonicalValue::Kind::Integer) {
                return std::unexpected(invalid("attempt " + std::string(attemptId) + " states a non-integer scale"));
            }
            scaleExponent = kScale->integer();
        }
        if (scaleExponent < kMinimumScaleExponent || scaleExponent > kMaximumScaleExponent) {
            return std::unexpected(
                exceeded("attempt " + std::string(attemptId) + " states a scale exponent outside the accepted range"));
        }

        // Two observations of one declared metric contradict each other, and
        // choosing between them is exactly the judgement an evaluator must not
        // make. Identity in the registry is one entry, so it is one value here.
        if (!observations.emplace(*metricId, Observation{*value, scaleExponent}).second) {
            return std::unexpected(
                invalid("attempt " + std::string(attemptId) + " reports " + *metricId + " more than once"));
        }
    }
    return observations;
}

// The attempt identities the set declared eligible, paired with the receipt
// descriptor the set recorded for each. An eligible identity with no attempt,
// or an eligible attempt with no receipt, is a contradiction inside the set and
// not something to work around.
RecordResult<std::vector<std::pair<std::string, Descriptor>>> readEligibleAttempts(const CanonicalValue& evidenceSet) {
    const auto* kAttempts = evidenceSet.find("attempts");
    const auto* kEligible = evidenceSet.find("eligibleAttemptIds");
    if (kAttempts == nullptr || kAttempts->kind() != CanonicalValue::Kind::Array || kEligible == nullptr ||
        kEligible->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(invalid("evidence set declares no attempts or no eligible identities"));
    }
    if (kEligible->elements().size() > kMaximumPlannedAttempts) {
        return std::unexpected(exceeded("evidence set declares more eligible attempts than the accepted bound"));
    }

    std::set<std::string, std::less<>> eligible;
    for (const auto& kIdentity : kEligible->elements()) {
        if (kIdentity.kind() != CanonicalValue::Kind::String) {
            return std::unexpected(invalid("an eligible identity is not a string"));
        }
        if (!eligible.insert(kIdentity.text()).second) {
            return std::unexpected(invalid("evidence set names " + kIdentity.text() + " eligible twice"));
        }
    }

    // Attempt order, not eligible-list order. The set's declared ordinal order
    // is the one ordering in it that means something, and reading the eligible
    // list in its own order would let a reordered list reorder a receipt.
    std::vector<std::pair<std::string, Descriptor>> resolved;
    for (const auto& kAttempt : kAttempts->elements()) {
        const auto* kIdentity = kAttempt.find("attemptId");
        if (kIdentity == nullptr || kIdentity->kind() != CanonicalValue::Kind::String) {
            return std::unexpected(invalid("an attempt declares no identity"));
        }
        if (eligible.erase(kIdentity->text()) == 0) {
            continue;
        }
        const auto* kReceipt = kAttempt.find("receipt");
        if (kReceipt == nullptr || kReceipt->kind() != CanonicalValue::Kind::Object) {
            return std::unexpected(
                invalid("attempt " + kIdentity->text() + " is eligible but carries no receipt descriptor"));
        }
        auto descriptor = parseDescriptor(*kReceipt);
        if (!descriptor) {
            return std::unexpected(descriptor.error());
        }
        resolved.emplace_back(kIdentity->text(), std::move(*descriptor));
    }
    if (!eligible.empty()) {
        return std::unexpected(invalid("evidence set names " + *eligible.begin() + " eligible but never declares it"));
    }
    return resolved;
}

CanonicalValue scaledValue(std::int64_t value, std::int64_t scaleExponent) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("value", CanonicalValue::makeInteger(value));
    members.emplace_back("scaleExponent", CanonicalValue::makeInteger(scaleExponent));
    return CanonicalValue::makeObject(std::move(members));
}

CanonicalValue descriptorMember(std::string identity, const Descriptor& descriptor) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("attemptId", CanonicalValue::makeString(std::move(identity)));
    members.emplace_back("descriptor", describeAsValue(descriptor));
    return CanonicalValue::makeObject(std::move(members));
}

// One evaluated check, held until every phase has been decided so that the
// emitted order is the phase order rather than the order things were computed.
struct EvaluatedCheck {
    const BoundPolicyEntry* bound = nullptr;
    CheckPhase phase = CheckPhase::Correctness;
    CheckOutcome outcome = CheckOutcome::NotRun;
    CheckReason reason = CheckReason::None;
    std::vector<CanonicalValue> observations;
};

CanonicalValue checkValue(const EvaluatedCheck& check) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("policyKey", CanonicalValue::makeString(check.bound->entry->policyKey));
    members.emplace_back("phase", CanonicalValue::makeString(std::string(phaseName(check.phase))));
    members.emplace_back("checkClass",
                         CanonicalValue::makeString(check.bound->entry->checkClass == CheckClass::Completeness
                                                        ? "completeness"
                                                        : "correctness"));
    members.emplace_back("metricId", CanonicalValue::makeString(check.bound->entry->metricId));
    members.emplace_back("metricGeneration", CanonicalValue::makeInteger(check.bound->entry->metricGeneration));
    members.emplace_back("budgetClass", CanonicalValue::makeString(check.bound->metric->budgetClass));
    members.emplace_back(
        "comparison",
        CanonicalValue::makeString(check.bound->entry->comparison == Comparison::AtMost ? "at_most" : "at_least"));
    // The bound is recorded exactly as the policy wrote it, unmoved. Recording
    // a rescaled bound would make the receipt state a threshold the authority
    // never set, which is the quiet way a threshold moves.
    members.emplace_back("bound", scaledValue(check.bound->entry->boundValue, check.bound->entry->boundScaleExponent));
    members.emplace_back("outcome", CanonicalValue::makeString(std::string(outcomeName(check.outcome))));
    if (check.reason != CheckReason::None) {
        members.emplace_back("reason", CanonicalValue::makeString(std::string(reasonName(check.reason))));
    }
    members.emplace_back("observations", CanonicalValue::makeArray(check.observations));
    return CanonicalValue::makeObject(std::move(members));
}

CanonicalValue claimScopeValue() {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("performanceClaim", CanonicalValue::makeBoolean(false));
    members.emplace_back("runnerClaim", CanonicalValue::makeBoolean(false));
    members.emplace_back("trustedProvenanceClaim", CanonicalValue::makeBoolean(false));
    members.emplace_back("promotionClaim", CanonicalValue::makeBoolean(false));
    members.emplace_back("relativeComparisonClaim", CanonicalValue::makeBoolean(false));
    return CanonicalValue::makeObject(std::move(members));
}

} // namespace

RecordResult<CanonicalValue> evaluateEvidenceSet(const BlobStore& store,
                                                 const EvaluationInputs& inputs,
                                                 const CanonicalValue& evidenceSet,
                                                 const MetricRegistry& registry,
                                                 const EvaluationPolicy& policy,
                                                 std::string_view evaluationId) {
    // Identity first, and every part of it before any observation is read. An
    // evaluator that reached a metric before proving what it was reading would
    // be deciding about bytes it had not yet identified.
    if (auto status = checkProducerAuthority(evidenceSet); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkRecordKind(evidenceSet, kEvidenceSetRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(inputs.repositoryRoot, kEvidenceSetSchemaPath, inputs.evidenceSetPath);
        !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationMatches(evidenceSet, kEvidenceSetMediaType, kEvidenceSetGeneration); !status) {
        return std::unexpected(status.error());
    }

    auto tier = readRequiredText(evidenceSet, "tier");
    if (!tier) {
        return std::unexpected(tier.error());
    }
    if (*tier != kTier0) {
        return std::unexpected(invalid("evidence set claims tier " + *tier + ", which this gate cannot evaluate"));
    }
    if (*tier != policy.tier) {
        return std::unexpected(mismatched("the evidence set and the policy claim different tiers"));
    }

    const auto* kCompatibility = evidenceSet.find("compatibility");
    if (kCompatibility == nullptr || kCompatibility->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("evidence set declares no compatibility facts"));
    }
    auto setRegistryGeneration = readRequiredInteger(*kCompatibility, "metricRegistryGeneration");
    if (!setRegistryGeneration) {
        return std::unexpected(setRegistryGeneration.error());
    }
    if (*setRegistryGeneration != registry.registryGeneration) {
        return std::unexpected(mismatched("the evidence set was produced against another metric registry generation"));
    }

    // Resolution before comparison. An entry binding an undeclared metric, a
    // diagnostic one, or a budget class no Tier-0 check may attach to fails the
    // whole evaluation rather than one check, because the policy as a whole is
    // then not a thing this gate can apply.
    auto bound = bindPolicyToRegistry(policy, registry);
    if (!bound) {
        return std::unexpected(bound.error());
    }

    auto eligible = readEligibleAttempts(evidenceSet);
    if (!eligible) {
        return std::unexpected(eligible.error());
    }

    std::vector<EligibleRun> runs;
    std::vector<CanonicalValue> receiptInputs;
    runs.reserve(eligible->size());
    receiptInputs.reserve(eligible->size());
    for (const auto& [kIdentity, kDescriptor] : *eligible) {
        // The store's own typed reason is carried through rather than replaced
        // by a general one, so a missing blob and a corrupt blob stay
        // distinguishable at the point a reader looks at the failure.
        auto bytes = store.get(kDescriptor.digest);
        if (!bytes) {
            return std::unexpected(mismatched("attempt " + kIdentity + " names receipt " + kDescriptor.digest + ": " +
                                              blobRejectionName(bytes.error().rejection) + ", " +
                                              bytes.error().detail));
        }
        if (auto verified = verifyDescriptor(kDescriptor, *bytes, kRawRunReceiptMediaType); !verified) {
            return std::unexpected(verified.error());
        }
        auto record = ingestCanonicalBytes(*bytes);
        if (!record) {
            return std::unexpected(record.error());
        }
        auto path = store.pathFor(kDescriptor.digest);
        if (!path) {
            return std::unexpected(
                mismatched("receipt " + kDescriptor.digest + ": " + blobRejectionName(path.error().rejection)));
        }
        auto summary = validateRawRunReceipt(inputs.repositoryRoot, *path, *record, kRawRunReceiptMediaType);
        if (!summary) {
            return std::unexpected(summary.error());
        }
        auto receiptGeneration = readRequiredInteger(*record, "metricRegistryGeneration");
        if (!receiptGeneration) {
            return std::unexpected(receiptGeneration.error());
        }
        if (*receiptGeneration != registry.registryGeneration) {
            return std::unexpected(
                mismatched("attempt " + kIdentity + " was produced against another metric registry generation"));
        }
        auto observations = readObservations(*record, registry, kIdentity);
        if (!observations) {
            return std::unexpected(observations.error());
        }
        runs.push_back(EligibleRun{kIdentity, kDescriptor, std::move(*observations)});
        receiptInputs.push_back(descriptorMember(kIdentity, kDescriptor));
    }

    // Phase order, then key. Sorting by key rather than by the policy file's
    // own array order keeps the emitted receipt independent of how the
    // maintained policy happens to be laid out.
    std::vector<EvaluatedCheck> checks;
    checks.reserve(bound->size());
    for (const auto& kEntry : *bound) {
        checks.push_back(EvaluatedCheck{&kEntry, phaseOf(kEntry), CheckOutcome::NotRun, CheckReason::None, {}});
    }
    std::ranges::sort(checks, [](const EvaluatedCheck& left, const EvaluatedCheck& right) {
        if (left.phase != right.phase) {
            return left.phase < right.phase;
        }
        return left.bound->entry->policyKey < right.bound->entry->policyKey;
    });

    constexpr std::array kPhases{CheckPhase::Completeness, CheckPhase::Correctness, CheckPhase::HardCeiling};
    bool blocked = false;
    CheckPhase blockingPhase = CheckPhase::Completeness;
    for (const CheckPhase kPhase : kPhases) {
        if (blocked) {
            break;
        }
        bool phaseFailed = false;
        for (auto& check : checks) {
            if (check.phase != kPhase) {
                continue;
            }
            bool satisfied = true;
            std::size_t silent = 0;
            for (const auto& kRun : runs) {
                const auto kFound = kRun.observations.find(check.bound->entry->metricId);
                if (kFound == kRun.observations.end()) {
                    ++silent;
                    continue;
                }
                auto compared = compareAt(*check.bound, kFound->second, kRun.attemptId);
                if (!compared) {
                    return std::unexpected(compared.error());
                }
                check.observations.push_back(CanonicalValue::makeObject(
                    {CanonicalValue::Member{"attemptId", CanonicalValue::makeString(kRun.attemptId)},
                     CanonicalValue::Member{"value", CanonicalValue::makeInteger(compared->observed)},
                     CanonicalValue::Member{"scaleExponent", CanonicalValue::makeInteger(compared->scaleExponent)}}));
                if (!satisfies(check.bound->entry->comparison, compared->observed, compared->bound)) {
                    satisfied = false;
                }
            }
            // Every eligible run must meet the bound, and a run that reported
            // nothing has not met it. One silent run is enough: deciding from
            // the runs that happened to report is how a missing observation
            // becomes an accidental pass, and a quiet run is indistinguishable
            // from a run whose result nobody wanted recorded.
            //
            // A missing observation is reported ahead of a violated bound when
            // both are present, because a comparison made across incomplete
            // evidence has not established what the other runs would have said.
            if (silent > 0 || runs.empty()) {
                check.outcome = CheckOutcome::Failed;
                check.reason = CheckReason::ObservationMissing;
                phaseFailed = true;
                continue;
            }
            if (!satisfied) {
                check.outcome = CheckOutcome::Failed;
                check.reason = CheckReason::BoundViolated;
                phaseFailed = true;
                continue;
            }
            check.outcome = CheckOutcome::Passed;
        }
        if (phaseFailed) {
            blocked = true;
            blockingPhase = kPhase;
        }
    }
    for (auto& check : checks) {
        if (check.outcome == CheckOutcome::NotRun) {
            check.reason = CheckReason::EarlierPhaseFailed;
        }
    }

    std::vector<CanonicalValue> checkValues;
    std::int64_t failedCount = 0;
    std::int64_t notRunCount = 0;
    checkValues.reserve(checks.size());
    for (const auto& kCheck : checks) {
        failedCount += kCheck.outcome == CheckOutcome::Failed ? 1 : 0;
        notRunCount += kCheck.outcome == CheckOutcome::NotRun ? 1 : 0;
        checkValues.push_back(checkValue(kCheck));
    }

    std::vector<CanonicalValue::Member> verdict;
    verdict.emplace_back("outcome", CanonicalValue::makeString(blocked ? "failed" : "passed"));
    if (blocked) {
        verdict.emplace_back("blockingPhase", CanonicalValue::makeString(std::string(phaseName(blockingPhase))));
    }
    verdict.emplace_back("checkCount", CanonicalValue::makeInteger(static_cast<std::int64_t>(checks.size())));
    verdict.emplace_back("failedCheckCount", CanonicalValue::makeInteger(failedCount));
    verdict.emplace_back("notRunCheckCount", CanonicalValue::makeInteger(notRunCount));

    std::vector<CanonicalValue::Member> inputMembers;
    inputMembers.emplace_back("evidenceSet", describeAsValue(inputs.evidenceSetDescriptor));
    inputMembers.emplace_back("metricRegistry", describeAsValue(inputs.metricRegistryDescriptor));
    inputMembers.emplace_back("evaluationPolicy", describeAsValue(inputs.evaluationPolicyDescriptor));
    inputMembers.emplace_back("receipts", CanonicalValue::makeArray(std::move(receiptInputs)));

    std::vector<CanonicalValue::Member> trust;
    trust.emplace_back("provenance", CanonicalValue::makeString("diagnostic_untrusted"));

    std::vector<CanonicalValue::Member> members;
    members.emplace_back("schemaVersion", CanonicalValue::makeInteger(kEvaluationReceiptGeneration));
    members.emplace_back("recordKind", CanonicalValue::makeString(std::string(kEvaluationReceiptRecordKind)));
    members.emplace_back("evaluationId", CanonicalValue::makeString(std::string(evaluationId)));
    members.emplace_back("evaluatorGeneration", CanonicalValue::makeInteger(kEvaluatorGeneration));
    members.emplace_back("tier", CanonicalValue::makeString(std::string(kTier0)));
    members.emplace_back("metricRegistryGeneration", CanonicalValue::makeInteger(registry.registryGeneration));
    members.emplace_back("policyGeneration", CanonicalValue::makeInteger(policy.policyGeneration));
    members.emplace_back("inputs", CanonicalValue::makeObject(std::move(inputMembers)));
    members.emplace_back("checks", CanonicalValue::makeArray(std::move(checkValues)));
    members.emplace_back("verdict", CanonicalValue::makeObject(std::move(verdict)));
    members.emplace_back("claimScope", claimScopeValue());
    members.emplace_back("trust", CanonicalValue::makeObject(std::move(trust)));
    return CanonicalValue::makeObject(std::move(members));
}

} // namespace rawframe::tool::evidence
