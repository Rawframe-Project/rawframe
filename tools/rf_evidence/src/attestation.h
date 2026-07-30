#pragma once

#include "canonical_json.h"
#include "descriptor.h"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

// The in-toto and SLSA identities ADR-0082 accepts, and nothing else. A bundle
// that carries a different envelope, statement, or predicate type is refused
// rather than interpreted: this generation has exactly one accepted shape, and
// admitting a second reader now would be a compatibility path before there is
// anything to be compatible with.
inline constexpr std::string_view kSigstoreBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json";
inline constexpr std::string_view kInTotoPayloadType = "application/vnd.in-toto+json";
inline constexpr std::string_view kInTotoStatementType = "https://in-toto.io/Statement/v1";
inline constexpr std::string_view kSlsaProvenancePredicateType = "https://slsa.dev/provenance/v1";

// A provenance bundle is small. The ceiling is checked before the bytes are
// read, so a hostile input costs a stat rather than a parse.
inline constexpr std::size_t kMaximumBundleBytes = 262'144;

// The ADR-0082 producer identity, as constants rather than as configuration.
//
// These are contract constants, not tunables. ADR-0082 fixes each one exactly,
// and every one of them is a value a candidate would have to change in order to
// widen its own trust: the issuer, the certificate identity, the producing
// repository, and the workflow path together are the whole of what "produced by
// the protected lane" means. Reading them from a file the candidate can edit
// would hand the party being judged the definition of its own credential, which
// is the failure ADR-0082 exists to prevent. A change here is a reviewed change
// to a compiled tool and a new verification-policy revision, which is what it
// should cost.
inline constexpr std::string_view kTrustedCertificateIssuer = "https://token.actions.githubusercontent.com";

// The repository is compared in the form the statement actually carries, which
// is a URL rather than the `owner/name` shorthand. This is measured rather than
// assumed: the real GitHub provenance bundle this repository already verifies
// for LLVM carries `https://github.com/llvm/llvm-project` in the same field.
inline constexpr std::string_view kTrustedSourceRepositoryUri = "https://github.com/Rawframe-Project/rawframe";

// The same repository in the shorthand the record schema requires of a claim.
//
// These are two spellings of one fact, and keeping only the first made every
// genuine attestation unverifiable: the statement carries the URL, the schema
// constrains a claim to `owner/name`, and the two were compared to each other
// directly, so a schema-valid claim could never match and a matching claim could
// never be schema-valid. The tests did not catch it because they build a claim
// and never validate it against the schema that governs one, which is why the
// first real bundle found it and eight hand-written cases did not.
inline constexpr std::string_view kTrustedSourceRepositoryPath = "Rawframe-Project/rawframe";

// The one protected ref. It is compared against the ref of the code that was
// verified and against the ref of the workflow that entered the lane, because a
// reusable producer pinned at the protected ref can be called from a branch, and
// then the signed identity would be the protected one while the bytes it signed
// came from somewhere else.
inline constexpr std::string_view kTrustedProtectedRef = "refs/heads/main";

// The two workflow paths, kept apart because the provenance keeps them apart.
//
// A reusable workflow's provenance names the entry point in
// `externalParameters.workflow.path` and the workflow that actually signed in
// `runDetails.builder.id`. The LLVM bundle already verified here proves it:
// its external parameters name `release-tasks.yml` while its builder identity
// names the reusable `release-binaries.yml`. Checking only one of them would
// leave the other unconstrained, so both are named exactly.
inline constexpr std::string_view kTrustedProducerWorkflowPath = ".github/workflows/trusted-verification.yml";
inline constexpr std::string_view kTrustedEntryWorkflowPath = ".github/workflows/verify-main.yml";

// The one runner environment ADR-0082 admits.
//
// The decision says the producing lane runs on GitHub-hosted runners and
// explicitly rejects self-hosted runners for it. Until this constant existed
// that was a sentence in a document: a self-hosted runner in this organization,
// entering through the protected ref, would receive a certificate with the same
// issuer and the same identity, and would have verified as `trusted_ci`. The
// provenance names the environment in `internalParameters.github`, so the
// requirement can be mechanical instead of remembered, and it is checked here
// rather than trusted from a claim, because the claim is written by the same
// party the check is about.
inline constexpr std::string_view kTrustedRunnerEnvironment = "github-hosted";

// The certificate identity is matched literally. ADR-0082 forbids prefix,
// suffix, glob, and regular-expression matching here, because every one of them
// admits a near miss, and a near miss is what an attacker who controls a
// similarly named repository or workflow file has to offer.
//
// This is also the exact string the provenance carries as its builder identity,
// so requiring the two to agree ties what the certificate proves to what the
// payload claims about itself.
inline constexpr std::string_view kTrustedCertificateIdentity =
    "https://github.com/Rawframe-Project/rawframe/.github/workflows/trusted-verification.yml@refs/heads/main";

// What a record claims about its own provenance.
//
// Every member is an assertion until it has been checked against the bundle and
// the bundle has been checked against the pinned root. The type exists so that
// the claim and the proof stay two separate values that have to be compared,
// rather than one value that gets believed.
struct AttestationClaim {
    Descriptor bundle;
    std::string subjectName;
    std::string subjectDigest;
    std::string builderId;
    std::string sourceRepository;
    std::string sourceCommit;
    std::string sourceRef;
    std::string workflowPath;
    std::string workflowRef;
    std::int64_t runId = 0;
    std::int64_t runAttempt = 0;
};

// What the bundle actually says, decoded from its own bytes.
struct DecodedProvenance {
    std::string subjectName;
    std::string subjectDigest;
    std::string builderId;
    std::string sourceRepository;
    std::string sourceCommit;
    std::string sourceRef;
    std::string workflowPath;
    std::string workflowRef;
    std::int64_t runId = 0;
    std::int64_t runAttempt = 0;
};

// Where the local bytes and the offline verifier are.
//
// There is no network member and there is no place to put one. ADR-0022 makes
// repository tooling offline, and a verification that could reach out would be
// a verification whose result depends on who answered.
struct AttestationInputs {
    std::filesystem::path bundlePath;
    std::filesystem::path subjectPath;
    std::filesystem::path cosign;
    std::filesystem::path trustedRoot;
};

// Why an attestation was refused. Each of ADR-0082's seven requirements can
// fail on its own and says so on its own, because a single "verification
// failed" makes a wrong digest and a forged issuer look like the same event.
enum class AttestationRejection : std::uint8_t {
    ClaimMalformed,
    BundleUnreadable,
    BundleMalformed,
    EnvelopeMismatch,
    StatementMismatch,
    SubjectMismatch,
    BuilderMismatch,
    SourceMismatch,
    WorkflowMismatch,
    RunIdentityMissing,
    RunIdentityReplayed,
    RunnerEnvironmentUnadmitted,
    SignatureInvalid,
    VerifierUnavailable,
};

[[nodiscard]] constexpr const char* attestationRejectionName(AttestationRejection value) noexcept {
    switch (value) {
    case AttestationRejection::ClaimMalformed:
        return "claim_malformed";
    case AttestationRejection::BundleUnreadable:
        return "bundle_unreadable";
    case AttestationRejection::BundleMalformed:
        return "bundle_malformed";
    case AttestationRejection::EnvelopeMismatch:
        return "envelope_mismatch";
    case AttestationRejection::StatementMismatch:
        return "statement_mismatch";
    case AttestationRejection::SubjectMismatch:
        return "subject_mismatch";
    case AttestationRejection::BuilderMismatch:
        return "builder_mismatch";
    case AttestationRejection::SourceMismatch:
        return "source_mismatch";
    case AttestationRejection::WorkflowMismatch:
        return "workflow_mismatch";
    case AttestationRejection::RunIdentityMissing:
        return "run_identity_missing";
    case AttestationRejection::RunIdentityReplayed:
        return "run_identity_replayed";
    case AttestationRejection::RunnerEnvironmentUnadmitted:
        return "runner_environment_unadmitted";
    case AttestationRejection::SignatureInvalid:
        return "signature_invalid";
    case AttestationRejection::VerifierUnavailable:
        return "verifier_unavailable";
    }
    return "unknown_attestation_rejection";
}

struct AttestationFailure {
    AttestationRejection rejection;
    std::string detail;
};

template <typename ValueType> using AttestationResult = std::expected<ValueType, AttestationFailure>;

// Reads the claim out of a record's trust block. Shape errors are claim
// failures rather than schema failures: a caller reaches this after the schema
// has already admitted the record, so anything wrong here is a claim that is
// well formed and still unusable.
[[nodiscard]] AttestationResult<AttestationClaim> parseAttestationClaim(const CanonicalValue& attestation);

// Decodes the bundle's own statement without any cryptography, and checks the
// envelope, statement, and predicate identities while doing it. Separated from
// signature verification so that a malformed bundle is refused before a
// subprocess is started, and so the semantic rules can be tested without a
// signing key in the room.
[[nodiscard]] AttestationResult<DecodedProvenance> decodeProvenanceBundle(std::string_view bundleBytes);

// Recomputes the subject digest from the artifact's own bytes.
//
// ADR-0082 requires the digest to be recomputed locally rather than read from
// the statement, and this is that requirement: a statement that says what its
// subject hashes to is describing itself, and a description is not a check.
[[nodiscard]] AttestationResult<std::string> digestSubject(const std::filesystem::path& subjectPath);

// Verifies the bundle's signature offline through the locked Cosign against the
// pinned Sigstore trusted root, with the exact issuer and the literal
// certificate identity. Every ambient Sigstore setting is unset for the child
// process, so an environment variable cannot redirect the root or re-enable a
// network fetch.
[[nodiscard]] AttestationResult<void> verifyBundleSignature(const AttestationInputs& inputs,
                                                            std::string_view subjectDigest);

// The whole of ADR-0082's verification policy except the replay rule, which
// needs the ledger and therefore belongs to trust derivation.
[[nodiscard]] AttestationResult<DecodedProvenance> verifyAttestation(const AttestationClaim& claim,
                                                                     const AttestationInputs& inputs);

} // namespace rawframe::tool::evidence
