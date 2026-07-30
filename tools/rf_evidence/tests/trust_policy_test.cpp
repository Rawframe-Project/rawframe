#include "canonical_json.h"
#include "trust_policy.h"

#include <array>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

AttestationInputs absentInputs() {
    AttestationInputs inputs;
    inputs.bundlePath = "does-not-exist.sigstore.json";
    inputs.subjectPath = "does-not-exist.json";
    inputs.cosign = "does-not-exist-cosign";
    inputs.trustedRoot = "does-not-exist-trusted-root.json";
    return inputs;
}

TrustResult<TrustClass> deriveFromText(std::string_view canonicalTrust,
                                       std::span<const AdmittedRun> admitted = {}) {
    auto value = ingestCanonicalBytes(canonicalTrust);
    EXPECT_TRUE(value.has_value()) << "the fixture itself must be canonical: " << canonicalTrust;
    if (!value) {
        return std::unexpected(TrustFailure{TrustRejection::MalformedTrustBlock, "fixture is not canonical"});
    }
    return deriveTrustClass(*value, absentInputs(), admitted);
}

constexpr std::string_view kUntrusted = R"({"provenance":"diagnostic_untrusted"})";

} // namespace

TEST(TrustPolicy, AdmitsAnUntrustedRecordWithoutAskingItToProveAnything) {
    auto derived = deriveFromText(kUntrusted);
    ASSERT_TRUE(derived.has_value()) << (derived ? "" : derived.error().detail);
    EXPECT_EQ(*derived, TrustClass::DiagnosticUntrusted);
}

// Claiming less than you can prove is fine. Carrying proof you did not claim is
// two halves of a record disagreeing, and the disagreement is the finding.
TEST(TrustPolicy, RefusesAnUntrustedRecordThatCarriesAnAttestationAnyway) {
    constexpr std::string_view kContradictory =
        R"({"attestation":{"builderId":"b","bundle":{"byteLength":1,"digest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"},"runAttempt":1,"runId":1,"sourceCommit":"0123456789abcdef0123456789abcdef01234567","sourceRef":"refs/heads/main","sourceRepository":"Rawframe-Project/rawframe","subjectDigest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","subjectName":"s","workflowPath":".github/workflows/trusted-verification.yml","workflowRef":"refs/heads/main"},"provenance":"diagnostic_untrusted"})";
    auto derived = deriveFromText(kContradictory);
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().rejection, TrustRejection::MalformedTrustBlock);
}

// SPEC-0017's typed reason for a claim with nothing behind it. It is not a
// demotion: a record that says trusted_ci and hands over no evidence fails,
// because filing a forgery attempt as a weaker result loses the attempt.
TEST(TrustPolicy, RefusesATrustedClaimThatCarriesNothingThatCouldProveIt) {
    auto derived = deriveFromText(R"({"provenance":"trusted_ci"})");
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().rejection, TrustRejection::ProvenanceUnavailable);
}

TEST(TrustPolicy, RefusesAProvenanceClassThisGenerationDoesNotDefine) {
    auto derived = deriveFromText(R"({"provenance":"trusted_local"})");
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().rejection, TrustRejection::TrustClaimUnsupported);
}

TEST(TrustPolicy, RefusesATrustBlockThatIsNotAnObjectOrCarriesNoProvenance) {
    auto missing = deriveFromText(R"({"reference":"anything"})");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().rejection, TrustRejection::MalformedTrustBlock);

    const CanonicalValue array = CanonicalValue::makeArray({});
    auto derived = deriveTrustClass(array, absentInputs(), {});
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().rejection, TrustRejection::MalformedTrustBlock);
}

// Every escalation SPEC-0017 forbids, checked as a list rather than asserted in
// prose. A new spelling has to be added deliberately, and this names what it
// refused so a regression cannot pass quietly.
TEST(TrustPolicy, RefusesEveryRequestThatWouldRaiseAuthorityFromOutsideTheEvidence) {
    const std::array<std::string_view, 10> kAttempts{
        "--trust=trusted_ci", "--trust",   "--tier=tier_2",       "--provenance=trusted_ci", "--trusted",
        "--trusted-ci",       "--promote", "--activate-baseline", "--force",                 "--repository-root",
    };
    const auto refused = refusedEscalationRequests(kAttempts);
    ASSERT_EQ(refused.size(), 9U);
    EXPECT_EQ(refused.front(), "--trust=trusted_ci");
    EXPECT_EQ(refused.back(), "--force");
    for (const std::string& entry : refused) {
        EXPECT_NE(entry, "--repository-root") << "an ordinary option must not be mistaken for an escalation";
    }
}

TEST(TrustPolicy, NamesEveryClassAndRejectionItCanReport) {
    EXPECT_STREQ(trustClassName(TrustClass::DiagnosticUntrusted), "diagnostic_untrusted");
    EXPECT_STREQ(trustClassName(TrustClass::TrustedCi), "trusted_ci");
    EXPECT_STREQ(trustRejectionName(TrustRejection::MalformedTrustBlock), "malformed_trust_block");
    EXPECT_STREQ(trustRejectionName(TrustRejection::ProvenanceUnavailable), "provenance_unavailable");
    EXPECT_STREQ(trustRejectionName(TrustRejection::TrustClaimUnsupported), "trust_claim_unsupported");
    EXPECT_STREQ(trustRejectionName(TrustRejection::AttestationRefused), "attestation_refused");
}

} // namespace rawframe::tool::evidence
