#pragma once

#include "attestation.h"
#include "blob_store.h"
#include "canonical_json.h"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

// The producer identity these classes are separated by lives in attestation.h,
// beside the code that enforces it. It is stated once, as a compiled constant,
// for the reason recorded there.

// The two provenance classes ADR-0019 defines. They are separated by whether an
// attestation verified, never by where a process believes it is running.
enum class TrustClass : std::uint8_t {
    DiagnosticUntrusted,
    TrustedCi,
};

[[nodiscard]] constexpr const char* trustClassName(TrustClass value) noexcept {
    switch (value) {
    case TrustClass::DiagnosticUntrusted:
        return "diagnostic_untrusted";
    case TrustClass::TrustedCi:
        return "trusted_ci";
    }
    return "unknown_trust_class";
}

// Why a claimed trust class was refused.
//
// SPEC-0017 already fixes the two typed reasons an unsupported claim produces,
// and both are preserved verbatim: a claim with nothing behind it is
// ProvenanceUnavailable, and a claim this generation cannot verify at all is
// TrustClaimUnsupported. A claim that is verifiable and false is neither, and
// carries the attestation rejection that refuted it.
enum class TrustRejection : std::uint8_t {
    MalformedTrustBlock,
    ProvenanceUnavailable,
    TrustClaimUnsupported,
    AttestationRefused,
};

[[nodiscard]] constexpr const char* trustRejectionName(TrustRejection value) noexcept {
    switch (value) {
    case TrustRejection::MalformedTrustBlock:
        return "malformed_trust_block";
    case TrustRejection::ProvenanceUnavailable:
        return "provenance_unavailable";
    case TrustRejection::TrustClaimUnsupported:
        return "trust_claim_unsupported";
    case TrustRejection::AttestationRefused:
        return "attestation_refused";
    }
    return "unknown_trust_rejection";
}

struct TrustFailure {
    TrustRejection rejection;
    std::string detail;
};

template <typename ValueType> using TrustResult = std::expected<ValueType, TrustFailure>;

// One run identity that has already been admitted, and the subject it was
// admitted for.
//
// The ledger is derived from records that already exist rather than maintained
// as its own mutable authority. A file that recorded which runs had been
// admitted would be a fourth thing to protect, and a candidate that could edit
// it could replay at will; a list rebuilt from immutable receipts cannot be
// edited without editing the receipts, which are content-addressed.
struct AdmittedRun {
    std::int64_t runId = 0;
    std::int64_t runAttempt = 0;
    std::string subjectDigest;
};

// Derives the trust class of one record from its trust block.
//
// The claimed value is never the answer. A record claiming diagnostic_untrusted
// is that, because claiming less than you can prove is not a security problem.
// A record claiming trusted_ci is that only once its attestation verifies
// offline against the pinned root, the exact issuer, and the literal
// certificate identity, and only when its run identity has not already been
// admitted for a different subject. A claim that fails is a typed failure and
// never a silent demotion, because demoting a forgery to a lower tier files it
// as a merely weaker result.
[[nodiscard]] TrustResult<TrustClass>
deriveTrustClass(const CanonicalValue& trust, const AttestationInputs& inputs, std::span<const AdmittedRun> admitted);

// The same derivation for one whole record, with the inputs resolved from what
// the repository already holds rather than from anything a caller supplies.
//
// The verifier is the prepared Cosign the offline lane proves against the
// artifact lock, and the two byte sequences are found in the local
// content-addressed store through the digests the claim itself carries. There
// is no parameter for either, and that is the point: a path option would let
// the party being judged choose which bytes its own credential was checked
// against, which is exactly the substitution ADR-0082 exists to prevent. A
// record can therefore only claim trust over bytes this repository already
// holds, which is the correct requirement, because a claim about bytes nobody
// has is not a claim anyone can check.
//
// A record with no trust block is making no claim, and an absent claim derives
// the untrusted class without needing a verifier at all. An empty prepared root
// means no host was named: that is not a permission to skip the check, it is a
// refused trusted claim, because a claim nothing can verify is unavailable
// rather than accepted.
[[nodiscard]] TrustResult<TrustClass> deriveRecordTrustClass(const CanonicalValue& record,
                                                             const std::filesystem::path& preparedToolsRoot,
                                                             const BlobStore& store,
                                                             std::span<const AdmittedRun> admitted);

// The escalation surface, stated as a function so it can be tested rather than
// asserted in prose. SPEC-0017 forbids raising authority through a flag, an
// environment variable, a directory label, a machine name, a username, or an
// editable annotation. This returns every such request it was handed, and the
// caller refuses all of them; it exists so that "none of these can escalate" is
// a check with a name instead of a property nobody measures.
[[nodiscard]] std::vector<std::string> refusedEscalationRequests(std::span<const std::string_view> arguments);

} // namespace rawframe::tool::evidence
