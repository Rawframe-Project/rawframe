#include "trust_policy.h"

#include <algorithm>
#include <array>
#include <utility>

namespace rawframe::tool::evidence {

namespace {

std::unexpected<TrustFailure> refuse(TrustRejection rejection, std::string detail) {
    return std::unexpected(TrustFailure{rejection, std::move(detail)});
}

// The vocabulary SPEC-0017 forbids from raising authority.
//
// It is a list rather than a rule because each entry is a concrete thing
// somebody has reached for: a flag, a tier request, an environment override, a
// provenance assertion, and the two verbs that belong to a reviewed human
// change. Naming them individually means a new one has to be added
// deliberately, and that the test that proves they are refused can name what it
// proved.
constexpr std::array<std::string_view, 8> kEscalationVocabulary{
    "--trust", "--tier", "--provenance", "--trusted", "--trusted-ci", "--promote", "--activate-baseline", "--force",
};

} // namespace

TrustResult<TrustClass> deriveTrustClass(const CanonicalValue& trust, const AttestationInputs& inputs,
                                         std::span<const AdmittedRun> admitted) {
    if (trust.kind() != CanonicalValue::Kind::Object) {
        return refuse(TrustRejection::MalformedTrustBlock, "the trust block is not an object");
    }
    const CanonicalValue* provenance = trust.find("provenance");
    if (provenance == nullptr || provenance->kind() != CanonicalValue::Kind::String) {
        return refuse(TrustRejection::MalformedTrustBlock, "the trust block carries no provenance string");
    }
    const CanonicalValue* attestation = trust.find("attestation");

    if (provenance->text() == trustClassName(TrustClass::DiagnosticUntrusted)) {
        // Claiming less than you can prove is not a security problem, so this
        // path needs no evidence. It does need the record to be honest about
        // what it carries: an untrusted record with an attestation attached is
        // a record whose two halves disagree, and the disagreement is the
        // finding.
        if (attestation != nullptr) {
            return refuse(TrustRejection::MalformedTrustBlock,
                          "an untrusted record carries an attestation it does not claim");
        }
        return TrustClass::DiagnosticUntrusted;
    }

    if (provenance->text() != trustClassName(TrustClass::TrustedCi)) {
        return refuse(TrustRejection::TrustClaimUnsupported,
                      "unsupported provenance class: " + provenance->text());
    }

    if (attestation == nullptr) {
        return refuse(TrustRejection::ProvenanceUnavailable,
                      "the record claims trusted_ci and carries nothing that could prove it");
    }

    auto claim = parseAttestationClaim(*attestation);
    if (!claim) {
        return refuse(TrustRejection::AttestationRefused,
                      std::string(attestationRejectionName(claim.error().rejection)) + ": " + claim.error().detail);
    }

    auto verified = verifyAttestation(*claim, inputs);
    if (!verified) {
        return refuse(TrustRejection::AttestationRefused,
                      std::string(attestationRejectionName(verified.error().rejection)) + ": "
                          + verified.error().detail);
    }

    // ADR-0082's seventh requirement. A run identity that has already been
    // admitted for a different subject is a replay: the signature over the old
    // statement is still perfectly valid, which is precisely why the signature
    // alone cannot answer this.
    const auto replayed = std::ranges::find_if(admitted, [&](const AdmittedRun& previous) {
        return previous.runId == verified->runId && previous.runAttempt == verified->runAttempt
               && previous.subjectDigest != verified->subjectDigest;
    });
    if (replayed != admitted.end()) {
        return refuse(TrustRejection::AttestationRefused,
                      std::string(attestationRejectionName(AttestationRejection::RunIdentityReplayed))
                          + ": run identity was already admitted for " + replayed->subjectDigest);
    }

    return TrustClass::TrustedCi;
}

std::vector<std::string> refusedEscalationRequests(std::span<const std::string_view> arguments) {
    std::vector<std::string> refused;
    for (const std::string_view argument : arguments) {
        // Both spellings are checked, because `--trust=trusted_ci` and
        // `--trust trusted_ci` are the same request and only one of them is a
        // bare token.
        const auto separator = argument.find('=');
        const std::string_view name = separator == std::string_view::npos ? argument : argument.substr(0, separator);
        if (std::ranges::find(kEscalationVocabulary, name) != kEscalationVocabulary.end()) {
            refused.emplace_back(argument);
        }
    }
    return refused;
}

} // namespace rawframe::tool::evidence
