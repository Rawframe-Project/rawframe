#include "baseline_record.h"

#include "descriptor.h"
#include "metric_registry.h"
#include "record_gate.h"

#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace rawframe::tool::evidence {

namespace {

RecordFailure invalid(std::string detail) {
    return RecordFailure{RecordRejection::SchemaInvalid, std::move(detail)};
}

RecordFailure exceeded(std::string detail) {
    return RecordFailure{RecordRejection::LimitExceeded, std::move(detail)};
}

// A promotion defect projected into the shared rejection vocabulary, with the
// typed name kept at the front of the detail so a caller reading text can still
// recover which defect fired. The type is the authority; the string is how it
// travels through a surface that predates it.
RecordFailure defect(BaselineDefect which, std::string detail) {
    return invalid(std::string(baselineDefectName(which)) + ": " + std::move(detail));
}

RecordResult<std::string> readDigest(const CanonicalValue& parent, std::string_view name) {
    const auto* kDescriptor = parent.find(name);
    if (kDescriptor == nullptr || kDescriptor->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no " + std::string(name) + " descriptor"));
    }
    return readRequiredText(*kDescriptor, "digest");
}

RecordResult<BaselineRole> readRole(const CanonicalValue& record) {
    auto text = readRequiredText(record, "role");
    if (!text) {
        return std::unexpected(text.error());
    }
    if (*text == "anchor") {
        return BaselineRole::Anchor;
    }
    if (*text == "rolling_main") {
        return BaselineRole::RollingMain;
    }
    return std::unexpected(invalid("baseline record declares an unknown role: " + *text));
}

RecordResult<BaselineState> readState(const CanonicalValue& status) {
    auto text = readRequiredText(status, "state");
    if (!text) {
        return std::unexpected(text.error());
    }
    if (*text == "active") {
        return BaselineState::Active;
    }
    if (*text == "superseded") {
        return BaselineState::Superseded;
    }
    if (*text == "revoked") {
        return BaselineState::Revoked;
    }
    return std::unexpected(invalid("baseline record declares an unknown status: " + *text));
}

// A margin is only meaningful against something this record says it covers.
// An entry naming an unlisted metric is a claim smuggled past the affected
// list, which is the list a reviewer actually reads.
RecordStatus checkHeadroomScope(const CanonicalValue& headroom,
                                std::string_view group,
                                const std::set<std::string, std::less<>>& affected) {
    const auto* kGroup = headroom.find(group);
    if (kGroup == nullptr || kGroup->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(invalid("baseline record declares no " + std::string(group) + " headroom array"));
    }
    if (group == "relative" && !kGroup->elements().empty()) {
        return std::unexpected(defect(BaselineDefect::IncompatibleScope,
                                      "relative headroom requires a qualified cell, which no tier_0 record has"));
    }
    for (const auto& kEntry : kGroup->elements()) {
        auto metricId = readRequiredText(kEntry, "metricId");
        if (!metricId) {
            return std::unexpected(metricId.error());
        }
        if (!affected.contains(*metricId)) {
            return std::unexpected(defect(BaselineDefect::IncompatibleScope,
                                          "headroom names " + *metricId + ", which the record does not affect"));
        }
    }
    return {};
}

} // namespace

RecordResult<BaselineRecord> parseBaselineRecord(const std::filesystem::path& repositoryRoot,
                                                 const std::filesystem::path& instancePath,
                                                 const CanonicalValue& record) {
    // checkProducerAuthority is deliberately not called here, and the caller
    // gates this kind ahead of it. That check refuses any member named
    // "promoted", "verdict", or "passed", and this record exists to name all
    // three: it points at a passing verdict and says what was promoted. Holding
    // a promotion pointer to a producer's restriction would make the fourth
    // authority unrepresentable, exactly as it would the third.
    if (auto status = checkRecordKind(record, kBaselineRecordRecordKind); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = validateAgainstSchema(repositoryRoot, kBaselineRecordSchemaPath, instancePath); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkGenerationMatches(record, kBaselineRecordMediaType, kBaselineRecordGeneration); !status) {
        return std::unexpected(status.error());
    }

    BaselineRecord parsed;
    auto baselineId = readRequiredText(record, "baselineId");
    if (!baselineId) {
        return std::unexpected(baselineId.error());
    }
    parsed.baselineId = std::move(*baselineId);

    auto role = readRole(record);
    if (!role) {
        return std::unexpected(role.error());
    }
    parsed.role = *role;

    auto tier = readRequiredText(record, "tier");
    if (!tier) {
        return std::unexpected(tier.error());
    }
    if (*tier != "tier_0") {
        return std::unexpected(defect(BaselineDefect::IncompatibleScope,
                                      "record claims tier " + *tier + ", which this gate cannot reach"));
    }

    const auto* kTrust = record.find("trust");
    if (kTrust == nullptr || kTrust->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no trust"));
    }
    auto provenance = readRequiredText(*kTrust, "provenance");
    if (!provenance) {
        return std::unexpected(provenance.error());
    }
    if (*provenance != "diagnostic_untrusted") {
        return std::unexpected(defect(BaselineDefect::UnsupportedProvenance,
                                      "record claims provenance " + *provenance + ", which this gate cannot produce"));
    }
    // A provenance reference this tool cannot resolve offline is a reference to
    // a trust decision made somewhere else. The tool performs no network access
    // on any path, so a remote scheme here would be a claim it can never check.
    if (const auto* kReference = kTrust->find("reference");
        kReference != nullptr && kReference->text().contains("://")) {
        return std::unexpected(defect(BaselineDefect::UnsupportedProvenance,
                                      "provenance points at " + kReference->text() + ", which is not verifiable here"));
    }

    const auto* kCompatibility = record.find("compatibility");
    if (kCompatibility == nullptr || kCompatibility->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no compatibility key"));
    }
    auto profileId = readRequiredText(*kCompatibility, "profileId");
    if (!profileId) {
        return std::unexpected(profileId.error());
    }
    parsed.profileId = std::move(*profileId);

    const auto* kPromoted = record.find("promoted");
    if (kPromoted == nullptr || kPromoted->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record points at nothing"));
    }
    auto receiptDigest = readDigest(*kPromoted, "evaluationReceipt");
    if (!receiptDigest) {
        return std::unexpected(receiptDigest.error());
    }
    auto setDigest = readDigest(*kPromoted, "evidenceSet");
    if (!setDigest) {
        return std::unexpected(setDigest.error());
    }
    if (*receiptDigest == *setDigest) {
        return std::unexpected(defect(BaselineDefect::MissingEvidence,
                                      "one artifact stands in for both the evaluation receipt and the evidence set"));
    }
    parsed.evaluationReceiptDigest = std::move(*receiptDigest);
    parsed.evidenceSetDigest = std::move(*setDigest);

    const auto* kSource = record.find("source");
    if (kSource == nullptr || kSource->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no candidate source"));
    }
    auto revision = readRequiredText(*kSource, "revision");
    if (!revision) {
        return std::unexpected(revision.error());
    }

    const auto* kPromotion = record.find("promotion");
    if (kPromotion == nullptr || kPromotion->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no promotion"));
    }
    auto reviewReference = readRequiredText(*kPromotion, "reviewReference");
    if (!reviewReference) {
        return std::unexpected(reviewReference.error());
    }
    auto changeReference = readRequiredText(*kPromotion, "protectedChangeReference");
    if (!changeReference) {
        return std::unexpected(changeReference.error());
    }
    if (*changeReference == *revision) {
        return std::unexpected(
            defect(BaselineDefect::SelfUpdate, "the protected change being approved is the candidate revision itself"));
    }
    if (*reviewReference == *changeReference) {
        return std::unexpected(
            defect(BaselineDefect::SelfPromotion, "the review of the change is the change, so nothing reviewed it"));
    }
    if (*reviewReference == parsed.evaluationReceiptDigest) {
        return std::unexpected(defect(BaselineDefect::CandidateControlledPolicy,
                                      "the candidate's own evaluation stands in for the protected review"));
    }
    auto owner = readRequiredText(*kPromotion, "approvingProjectOwner");
    if (!owner) {
        return std::unexpected(owner.error());
    }
    parsed.approvingProjectOwner = std::move(*owner);
    auto approvalTimestamp = readRequiredText(*kPromotion, "approvalTimestamp");
    if (!approvalTimestamp) {
        return std::unexpected(approvalTimestamp.error());
    }
    parsed.approvalTimestamp = std::move(*approvalTimestamp);

    const auto* kPredecessor = record.find("predecessor");
    if (kPredecessor == nullptr || kPredecessor->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no predecessor relationship"));
    }
    const auto* kFirst = kPredecessor->find("firstBaseline");
    const auto* kPredecessorDescriptor = kPredecessor->find("descriptor");
    if (kFirst == nullptr && kPredecessorDescriptor == nullptr) {
        return std::unexpected(defect(BaselineDefect::MissingPredecessor,
                                      "neither a first-baseline marker nor a predecessor, so the chain has a gap"));
    }
    if (kFirst != nullptr && kPredecessorDescriptor != nullptr) {
        return std::unexpected(
            defect(BaselineDefect::MissingPredecessor, "the record is both the first baseline and a successor to one"));
    }
    parsed.firstBaseline = kFirst != nullptr;
    if (kPredecessorDescriptor != nullptr) {
        auto predecessorDigest = readRequiredText(*kPredecessorDescriptor, "digest");
        if (!predecessorDigest) {
            return std::unexpected(predecessorDigest.error());
        }
        parsed.predecessorDigest = std::move(*predecessorDigest);
    }
    if (const auto* kChain = kPredecessor->find("chain");
        kChain != nullptr && kChain->elements().size() > kMaximumPredecessorChain) {
        return std::unexpected(exceeded("baseline record declares more than 32 predecessor chain entries"));
    }

    const auto* kStatus = record.find("status");
    if (kStatus == nullptr || kStatus->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no status relationship"));
    }
    auto state = readState(*kStatus);
    if (!state) {
        return std::unexpected(state.error());
    }
    parsed.state = *state;
    const bool kHasSuccessor = kStatus->find("successor") != nullptr;
    if (parsed.state == BaselineState::Active && kHasSuccessor) {
        return std::unexpected(
            defect(BaselineDefect::MutableRole, "an active baseline names a successor, so one of the two is stale"));
    }
    if (parsed.state != BaselineState::Active && !kHasSuccessor) {
        return std::unexpected(
            defect(BaselineDefect::MutableRole, "the status changed without a successor authority naming this record"));
    }

    const auto* kAffected = record.find("affected");
    if (kAffected == nullptr || kAffected->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares nothing affected"));
    }
    const auto* kMetrics = kAffected->find("metrics");
    if (kMetrics == nullptr || kMetrics->kind() != CanonicalValue::Kind::Array) {
        return std::unexpected(invalid("baseline record declares no affected metrics array"));
    }
    if (kMetrics->elements().empty()) {
        return std::unexpected(
            defect(BaselineDefect::MissingEvidence, "the record affects no metric, so it is a reference for nothing"));
    }
    if (kMetrics->elements().size() > kMaximumAffectedMetrics) {
        return std::unexpected(exceeded("baseline record declares more than 64 affected metrics"));
    }
    std::set<std::string, std::less<>> affected;
    parsed.affectedMetrics.reserve(kMetrics->elements().size());
    for (const auto& kMetric : kMetrics->elements()) {
        if (kMetric.kind() != CanonicalValue::Kind::String) {
            return std::unexpected(invalid("baseline record declares a non-string affected metric"));
        }
        if (!affected.insert(kMetric.text()).second) {
            return std::unexpected(invalid("baseline record names the metric " + kMetric.text() + " twice"));
        }
        parsed.affectedMetrics.push_back(kMetric.text());
    }

    const auto* kHeadroom = record.find("headroom");
    if (kHeadroom == nullptr || kHeadroom->kind() != CanonicalValue::Kind::Object) {
        return std::unexpected(invalid("baseline record declares no headroom"));
    }
    if (auto status = checkHeadroomScope(*kHeadroom, "absolute", affected); !status) {
        return std::unexpected(status.error());
    }
    if (auto status = checkHeadroomScope(*kHeadroom, "relative", affected); !status) {
        return std::unexpected(status.error());
    }

    return parsed;
}

BaselineDefect promotionRefusal(const BaselineRecord& /*record*/) noexcept {
    // Nothing about the record is consulted, and that is the point. Every
    // record this tool can read carries diagnostic_untrusted provenance,
    // because the shared schema pins it, and SPEC-0014 never admits local
    // untrusted evidence for promotion. There is no well-formed record for
    // which a different answer would be correct, so there is no branch.
    return BaselineDefect::InsufficientTrust;
}

} // namespace rawframe::tool::evidence
