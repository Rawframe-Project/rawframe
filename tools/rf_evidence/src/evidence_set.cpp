#include "evidence_set.h"

#include "raw_run_receipt.h"
#include "record_gate.h"

#include <algorithm>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace rawframe::tool::evidence {

namespace {

std::unexpected<RecordFailure> reject(RecordRejection rejection, std::string detail) {
    return std::unexpected(RecordFailure{rejection, std::move(detail)});
}

RecordResult<std::string> requireString(const CanonicalValue& parent, std::string_view name, std::string_view context) {
    const auto* kValue = parent.find(name);
    if (kValue == nullptr || kValue->kind() != CanonicalValue::Kind::String) {
        return reject(RecordRejection::SchemaInvalid, std::string(context) + " carries no string " + std::string(name));
    }
    return kValue->text();
}

RecordResult<std::int64_t>
requireInteger(const CanonicalValue& parent, std::string_view name, std::string_view context) {
    const auto* kValue = parent.find(name);
    if (kValue == nullptr || kValue->kind() != CanonicalValue::Kind::Integer) {
        return reject(RecordRejection::SchemaInvalid,
                      std::string(context) + " carries no integer " + std::string(name));
    }
    return kValue->integer();
}

RecordResult<std::string>
requireNestedString(const CanonicalValue& record, std::string_view group, std::string_view name) {
    const auto* kGroup = record.find(group);
    if (kGroup == nullptr || kGroup->kind() != CanonicalValue::Kind::Object) {
        return reject(RecordRejection::SchemaInvalid, "receipt carries no " + std::string(group) + " group");
    }
    return requireString(*kGroup, name, group);
}

RecordResult<std::int64_t>
requireNestedInteger(const CanonicalValue& record, std::string_view group, std::string_view name) {
    const auto* kGroup = record.find(group);
    if (kGroup == nullptr || kGroup->kind() != CanonicalValue::Kind::Object) {
        return reject(RecordRejection::SchemaInvalid, "receipt carries no " + std::string(group) + " group");
    }
    return requireInteger(*kGroup, name, group);
}

CanonicalValue descriptorOrNull(bool present, const Descriptor& descriptor) {
    if (!present) {
        return CanonicalValue::makeNull();
    }
    return describeAsValue(descriptor);
}

CanonicalValue compatibilityValue(const CompatibilityFacts& facts) {
    std::vector<CanonicalValue::Member> members;
    members.emplace_back("profileId", CanonicalValue::makeString(facts.profileId));
    members.emplace_back("workloadFingerprint", CanonicalValue::makeString(facts.workloadFingerprint));
    members.emplace_back("targetId", CanonicalValue::makeString(facts.targetId));
    members.emplace_back("platformId", CanonicalValue::makeString(facts.platformId));
    members.emplace_back("configuration", CanonicalValue::makeString(facts.configuration));
    members.emplace_back("closureFingerprint", CanonicalValue::makeString(facts.closureFingerprint));
    members.emplace_back("harnessId", CanonicalValue::makeString(facts.harnessId));
    members.emplace_back("metricRegistryGeneration", CanonicalValue::makeInteger(facts.metricRegistryGeneration));
    members.emplace_back("runnerGeneration", CanonicalValue::makeInteger(facts.runnerGeneration));
    members.emplace_back("cellFingerprint", CanonicalValue::makeString(facts.cellFingerprint));
    return CanonicalValue::makeObject(std::move(members));
}

// The first place two receipts can disagree, named exactly. A caller learns
// which fact differs rather than that something did, because "incompatible" on
// its own is the kind of message that gets worked around instead of fixed.
std::string firstDisagreement(const CompatibilityFacts& left, const CompatibilityFacts& right) {
    if (left.profileId != right.profileId) {
        return "profileId";
    }
    if (left.workloadFingerprint != right.workloadFingerprint) {
        return "workloadFingerprint";
    }
    if (left.targetId != right.targetId) {
        return "targetId";
    }
    if (left.platformId != right.platformId) {
        return "platformId";
    }
    if (left.configuration != right.configuration) {
        return "configuration";
    }
    if (left.closureFingerprint != right.closureFingerprint) {
        return "closureFingerprint";
    }
    if (left.harnessId != right.harnessId) {
        return "harnessId";
    }
    if (left.metricRegistryGeneration != right.metricRegistryGeneration) {
        return "metricRegistryGeneration";
    }
    if (left.runnerGeneration != right.runnerGeneration) {
        return "runnerGeneration";
    }
    if (left.cellFingerprint != right.cellFingerprint) {
        return "cellFingerprint";
    }
    return {};
}

// Every planned attempt appears exactly once and the ordinals cover 1..N with
// no gap. This is what makes a cherry-picked plan detectable: a plan that drops
// an attempt to improve the evidence either contradicts its own attemptCount or
// leaves a hole in the ordinals, and both fail here.
RecordStatus checkScheduleAccounting(const AttemptPlan& plan) {
    const auto kDeclared = static_cast<std::size_t>(plan.attemptCount);
    if (plan.attempts.size() != kDeclared) {
        return reject(RecordRejection::SchemaInvalid,
                      "the plan declares " + std::to_string(kDeclared) + " attempts and lists " +
                          std::to_string(plan.attempts.size()));
    }
    std::set<std::int64_t> attemptOrdinals;
    std::set<std::int64_t> repetitionOrdinals;
    std::unordered_set<std::string> identities;
    for (const auto& kAttempt : plan.attempts) {
        if (!identities.insert(kAttempt.attemptId).second) {
            return reject(RecordRejection::SchemaInvalid, "two attempts claim identity " + kAttempt.attemptId);
        }
        if (!attemptOrdinals.insert(kAttempt.attemptOrdinal).second) {
            return reject(RecordRejection::SchemaInvalid,
                          "two attempts claim ordinal " + std::to_string(kAttempt.attemptOrdinal));
        }
        if (kAttempt.repetitionOrdinal > plan.repetitionCount) {
            return reject(RecordRejection::SchemaInvalid,
                          "attempt " + kAttempt.attemptId + " names a repetition outside the schedule");
        }
        repetitionOrdinals.insert(kAttempt.repetitionOrdinal);
    }
    std::int64_t expected = 1;
    for (const std::int64_t kOrdinal : attemptOrdinals) {
        if (kOrdinal != expected) {
            return reject(RecordRejection::SchemaInvalid,
                          "attempt ordinals skip " + std::to_string(expected) + ", so an attempt is unaccounted for");
        }
        ++expected;
    }
    // Every declared repetition must be attempted. A schedule of five that
    // lists attempts for four has lost one, whatever its attemptCount claims.
    for (std::int64_t repetition = 1; repetition <= plan.repetitionCount; ++repetition) {
        if (!repetitionOrdinals.contains(repetition)) {
            return reject(RecordRejection::SchemaInvalid,
                          "repetition " + std::to_string(repetition) + " has no attempt");
        }
    }
    return {};
}

// A retry links to what it replaces. The chain must terminate, stay inside the
// plan, and not loop, because a loop is how a superseded attempt could be made
// to disappear from the eligible set without ever being removed from it.
RecordStatus checkSupersedesChains(const AttemptPlan& plan) {
    std::unordered_map<std::string, const PlannedAttempt*> byIdentity;
    for (const auto& kAttempt : plan.attempts) {
        byIdentity.emplace(kAttempt.attemptId, &kAttempt);
    }
    for (const auto& kAttempt : plan.attempts) {
        std::unordered_set<std::string> seen{kAttempt.attemptId};
        const PlannedAttempt* current = &kAttempt;
        std::size_t depth = 0;
        while (!current->supersedesAttemptId.empty()) {
            const auto kFound = byIdentity.find(current->supersedesAttemptId);
            if (kFound == byIdentity.end()) {
                return reject(RecordRejection::SchemaInvalid,
                              "attempt " + current->attemptId + " supersedes an attempt outside the plan");
            }
            if (!seen.insert(current->supersedesAttemptId).second) {
                return reject(RecordRejection::SchemaInvalid,
                              "the supersedes chain through " + kAttempt.attemptId + " loops");
            }
            ++depth;
            if (depth > kMaximumSupersedesDepth) {
                return reject(RecordRejection::LimitExceeded,
                              "the supersedes chain through " + kAttempt.attemptId + " exceeds the depth limit");
            }
            current = kFound->second;
        }
    }
    return {};
}

} // namespace

RecordResult<CompatibilityFacts> readCompatibility(const CanonicalValue& receipt) {
    CompatibilityFacts facts;
    const auto assign = [](auto& target, auto source) -> RecordStatus {
        if (!source) {
            return std::unexpected(source.error());
        }
        target = *source;
        return {};
    };
    if (auto status = assign(facts.profileId, requireNestedString(receipt, "profile", "profileId")); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.workloadFingerprint, requireNestedString(receipt, "profile", "workloadFingerprint"));
        !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.targetId, requireNestedString(receipt, "build", "targetId")); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.platformId, requireNestedString(receipt, "build", "platformId")); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.configuration, requireNestedString(receipt, "build", "configuration")); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.closureFingerprint, requireNestedString(receipt, "build", "closureFingerprint"));
        !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.harnessId, requireNestedString(receipt, "harness", "harnessId")); !status) {
        return std::unexpected(status.error());
    }
    if (auto status =
            assign(facts.metricRegistryGeneration, requireInteger(receipt, "metricRegistryGeneration", "receipt"));
        !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.runnerGeneration, requireNestedInteger(receipt, "runner", "runnerGeneration"));
        !status) {
        return std::unexpected(status.error());
    }
    if (auto status = assign(facts.cellFingerprint, requireNestedString(receipt, "runner", "cellFingerprint"));
        !status) {
        return std::unexpected(status.error());
    }
    return facts;
}

RecordResult<std::string> readTerminalStatus(const CanonicalValue& receipt) {
    return requireString(receipt, "status", "receipt");
}

RecordResult<AttemptPlan> parseAttemptPlan(const std::filesystem::path& repositoryRoot,
                                           const std::filesystem::path& instancePath,
                                           const CanonicalValue& record) {
    if (auto status = checkProducerAuthority(record); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkRecordKind(record, kAttemptPlanRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(repositoryRoot, kAttemptPlanSchemaPath, instancePath); !status) {
        return std::unexpected(status.error());
    }

    AttemptPlan plan;
    auto planId = requireString(record, "planId", "plan");
    if (!planId) {
        return std::unexpected(planId.error());
    }
    plan.planId = *planId;
    auto tier = requireString(record, "tier", "plan");
    if (!tier) {
        return std::unexpected(tier.error());
    }
    plan.tier = *tier;

    const auto* kSchedule = record.find("schedule");
    if (kSchedule == nullptr || kSchedule->kind() != CanonicalValue::Kind::Object) {
        return reject(RecordRejection::SchemaInvalid, "plan carries no schedule");
    }
    auto repetitionCount = requireInteger(*kSchedule, "repetitionCount", "schedule");
    if (!repetitionCount) {
        return std::unexpected(repetitionCount.error());
    }
    plan.repetitionCount = *repetitionCount;
    auto attemptCount = requireInteger(*kSchedule, "attemptCount", "schedule");
    if (!attemptCount) {
        return std::unexpected(attemptCount.error());
    }
    plan.attemptCount = *attemptCount;

    const auto* kAttempts = record.find("attempts");
    if (kAttempts == nullptr || kAttempts->kind() != CanonicalValue::Kind::Array) {
        return reject(RecordRejection::SchemaInvalid, "plan carries no attempts array");
    }
    if (kAttempts->elements().size() > kMaximumPlannedAttempts) {
        return reject(RecordRejection::LimitExceeded, "the plan exceeds the planned attempt limit");
    }
    for (const auto& kEntry : kAttempts->elements()) {
        if (kEntry.kind() != CanonicalValue::Kind::Object) {
            return reject(RecordRejection::SchemaInvalid, "a plan attempt is not an object");
        }
        PlannedAttempt attempt;
        auto attemptId = requireString(kEntry, "attemptId", "attempt");
        if (!attemptId) {
            return std::unexpected(attemptId.error());
        }
        attempt.attemptId = *attemptId;
        auto attemptOrdinal = requireInteger(kEntry, "attemptOrdinal", "attempt");
        if (!attemptOrdinal) {
            return std::unexpected(attemptOrdinal.error());
        }
        attempt.attemptOrdinal = *attemptOrdinal;
        auto repetitionOrdinal = requireInteger(kEntry, "repetitionOrdinal", "attempt");
        if (!repetitionOrdinal) {
            return std::unexpected(repetitionOrdinal.error());
        }
        attempt.repetitionOrdinal = *repetitionOrdinal;
        if (const auto* kSupersedes = kEntry.find("supersedesAttemptId"); kSupersedes != nullptr) {
            if (kSupersedes->kind() != CanonicalValue::Kind::String) {
                return reject(RecordRejection::SchemaInvalid, "supersedesAttemptId is not a string");
            }
            attempt.supersedesAttemptId = kSupersedes->text();
        }
        const auto* kReceipt = kEntry.find("receipt");
        if (kReceipt == nullptr) {
            return reject(RecordRejection::SchemaInvalid, "attempt " + attempt.attemptId + " omits its receipt member");
        }
        if (kReceipt->kind() != CanonicalValue::Kind::Null) {
            auto descriptor = parseDescriptor(*kReceipt);
            if (!descriptor) {
                return std::unexpected(descriptor.error());
            }
            attempt.hasReceipt = true;
            attempt.receipt = *descriptor;
        }
        plan.attempts.push_back(std::move(attempt));
    }

    if (auto status = checkScheduleAccounting(plan); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkSupersedesChains(plan); !status) {
        return std::unexpected(status.error());
    }
    return plan;
}

RecordResult<CanonicalValue>
assembleEvidenceSet(const BlobStore& store, const AttemptPlan& plan, std::string_view evidenceSetId) {
    // Declared ordinal order, derived from the plan's own numbers. Nothing here
    // depends on the order the plan happened to list its attempts in, so two
    // plans that differ only in listing order assemble to identical bytes.
    std::vector<const PlannedAttempt*> ordered;
    ordered.reserve(plan.attempts.size());
    for (const auto& kAttempt : plan.attempts) {
        ordered.push_back(&kAttempt);
    }
    std::ranges::sort(ordered, {}, &PlannedAttempt::attemptOrdinal);

    bool haveCompatibility = false;
    CompatibilityFacts agreed;
    std::string agreedFrom;
    std::vector<CanonicalValue> attemptValues;
    std::vector<std::string> supersededIdentities;
    std::vector<std::pair<std::string, std::string>> statusById;
    attemptValues.reserve(ordered.size());

    for (const PlannedAttempt* attempt : ordered) {
        std::string status(kNoReceiptStatus);
        if (attempt->hasReceipt) {
            auto bytes = store.get(attempt->receipt.digest);
            if (!bytes) {
                return reject(RecordRejection::DescriptorMismatch,
                              "attempt " + attempt->attemptId +
                                  " names a receipt the store refused: " + bytes.error().detail);
            }
            // The descriptor must identify exactly these bytes before any of
            // their meaning is used. A receipt whose descriptor disagrees is
            // not a receipt this ledger has read.
            if (auto verified = verifyDescriptor(attempt->receipt, *bytes, attempt->receipt.mediaType); !verified) {
                return std::unexpected(verified.error());
            }
            auto receipt = parseCanonicalSubset(*bytes);
            if (!receipt) {
                return std::unexpected(receipt.error());
            }
            if (auto kind = checkRecordKind(*receipt, kRawRunReceiptRecordKind); !kind) {
                return std::unexpected(kind.error());
            }
            auto declaredStatus = readTerminalStatus(*receipt);
            if (!declaredStatus) {
                return std::unexpected(declaredStatus.error());
            }
            status = *declaredStatus;

            auto facts = readCompatibility(*receipt);
            if (!facts) {
                return std::unexpected(facts.error());
            }
            if (!haveCompatibility) {
                agreed = *facts;
                agreedFrom = attempt->attemptId;
                haveCompatibility = true;
            } else if (const std::string kDiffers = firstDisagreement(agreed, *facts); !kDiffers.empty()) {
                return reject(RecordRejection::DescriptorMismatch,
                              "attempts " + agreedFrom + " and " + attempt->attemptId + " disagree on " + kDiffers);
            }
        }

        if (!attempt->supersedesAttemptId.empty()) {
            supersededIdentities.push_back(attempt->supersedesAttemptId);
        }
        statusById.emplace_back(attempt->attemptId, status);

        std::vector<CanonicalValue::Member> members;
        members.emplace_back("attemptId", CanonicalValue::makeString(attempt->attemptId));
        members.emplace_back("attemptOrdinal", CanonicalValue::makeInteger(attempt->attemptOrdinal));
        members.emplace_back("repetitionOrdinal", CanonicalValue::makeInteger(attempt->repetitionOrdinal));
        members.emplace_back("status", CanonicalValue::makeString(status));
        members.emplace_back("receipt", descriptorOrNull(attempt->hasReceipt, attempt->receipt));
        if (!attempt->supersedesAttemptId.empty()) {
            members.emplace_back("supersedesAttemptId", CanonicalValue::makeString(attempt->supersedesAttemptId));
        }
        attemptValues.push_back(CanonicalValue::makeObject(std::move(members)));
    }

    if (!haveCompatibility) {
        return reject(RecordRejection::SchemaInvalid, "no attempt produced a receipt, so there are no facts to bind");
    }

    // Eligibility restates the statuses above and adds nothing. An attempt is
    // eligible when it completed and no retry superseded it. That a set can be
    // valid with nothing eligible is the point: emptiness is a fact for the
    // evaluator to read, not a failure for the ledger to raise.
    const std::unordered_set<std::string> kSuperseded(supersededIdentities.begin(), supersededIdentities.end());
    std::vector<CanonicalValue> eligible;
    for (const auto& [kIdentity, kStatus] : statusById) {
        if (kStatus == "completed" && !kSuperseded.contains(kIdentity)) {
            eligible.push_back(CanonicalValue::makeString(kIdentity));
        }
    }

    std::vector<CanonicalValue::Member> schedule;
    schedule.emplace_back("repetitionCount", CanonicalValue::makeInteger(plan.repetitionCount));
    schedule.emplace_back("attemptCount", CanonicalValue::makeInteger(plan.attemptCount));

    std::vector<CanonicalValue::Member> members;
    members.emplace_back("schemaVersion", CanonicalValue::makeInteger(kEvidenceSetGeneration));
    members.emplace_back("recordKind", CanonicalValue::makeString(std::string(kEvidenceSetRecordKind)));
    members.emplace_back("evidenceSetId", CanonicalValue::makeString(std::string(evidenceSetId)));
    members.emplace_back("planId", CanonicalValue::makeString(plan.planId));
    members.emplace_back("tier", CanonicalValue::makeString(plan.tier));
    members.emplace_back("compatibility", compatibilityValue(agreed));
    members.emplace_back("schedule", CanonicalValue::makeObject(std::move(schedule)));
    members.emplace_back("attempts", CanonicalValue::makeArray(std::move(attemptValues)));
    members.emplace_back("eligibleAttemptIds", CanonicalValue::makeArray(std::move(eligible)));
    // Trust is the shared record shape, not a bare word. Local assembly is
    // always Tier 0: this tool has no way to produce trusted CI provenance and
    // must not be able to claim it.
    std::vector<CanonicalValue::Member> trust;
    trust.emplace_back("provenance", CanonicalValue::makeString("diagnostic_untrusted"));
    members.emplace_back("trust", CanonicalValue::makeObject(std::move(trust)));
    return CanonicalValue::makeObject(std::move(members));
}

} // namespace rawframe::tool::evidence
