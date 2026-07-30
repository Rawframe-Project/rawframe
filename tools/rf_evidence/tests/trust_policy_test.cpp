#include "canonical_json.h"
#include "trust_policy.h"

#include <array>
#include <filesystem>
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

TrustResult<TrustClass> deriveFromText(std::string_view canonicalTrust, std::span<const AdmittedRun> admitted = {}) {
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
        R"({"attestation":{"builderId":"b","bundle":{"byteLength":1,"digest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"},"runAttempt":1,"runId":1,"sourceCommit":"0123456789abcdef0123456789abcdef01234567","sourceRef":"refs/heads/main","sourceRepository":"https://github.com/Rawframe-Project/rawframe","subjectDigest":"sha256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862","subjectName":"s","workflowPath":".github/workflows/trusted-verification.yml","workflowRef":"refs/heads/main"},"provenance":"diagnostic_untrusted"})";
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

    const CanonicalValue kArray = CanonicalValue::makeArray({});
    auto derived = deriveTrustClass(kArray, absentInputs(), {});
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().rejection, TrustRejection::MalformedTrustBlock);
}

// Every escalation SPEC-0017 forbids, checked as a list rather than asserted in
// prose. A new spelling has to be added deliberately, and this names what it
// refused so a regression cannot pass quietly.
TEST(TrustPolicy, RefusesEveryRequestThatWouldRaiseAuthorityFromOutsideTheEvidence) {
    const std::array<std::string_view, 10> kAttempts{
        "--trust=trusted_ci",
        "--trust",
        "--tier=tier_2",
        "--provenance=trusted_ci",
        "--trusted",
        "--trusted-ci",
        "--promote",
        "--activate-baseline",
        "--force",
        "--repository-root",
    };
    const auto kRefused = refusedEscalationRequests(kAttempts);
    ASSERT_EQ(kRefused.size(), 9U);
    EXPECT_EQ(kRefused.front(), "--trust=trusted_ci");
    EXPECT_EQ(kRefused.back(), "--force");
    for (const std::string& entry : kRefused) {
        EXPECT_NE(entry, "--repository-root") << "an ordinary option must not be mistaken for an escalation";
    }
}

// The whole-record entry point, which is what the validate operation calls.
namespace {

TrustResult<TrustClass> deriveRecord(std::string_view canonicalRecord, const std::filesystem::path& preparedTools) {
    auto value = ingestCanonicalBytes(canonicalRecord);
    EXPECT_TRUE(value.has_value()) << "the fixture itself must be canonical: " << canonicalRecord;
    if (!value) {
        return std::unexpected(TrustFailure{TrustRejection::MalformedTrustBlock, "fixture is not canonical"});
    }
    return deriveRecordTrustClass(*value, preparedTools, BlobStore("does-not-exist-store"), {});
}

// One claim shaped exactly as the schema requires, over bytes no store holds.
constexpr std::string_view kTrustedRecord =
    R"({"recordKind":"raw_run_receipt","trust":{"attestation":{"builderId":"https://github.com/Rawframe-Project/rawframe/.github/workflows/trusted-verification.yml@refs/heads/main","bundle":{"byteLength":11101,"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"},"runAttempt":1,"runId":30535694786,"sourceCommit":"dc9563e75e1144f5e296d9cb0d883c0fe2ca12ac","sourceRef":"refs/heads/main","sourceRepository":"https://github.com/Rawframe-Project/rawframe","subjectDigest":"sha256:03074dece2e6c4a99f66eae62f4f01b96343847e3300f8ac717268ab77de77ff","subjectName":"linux-x86_64-reports.tar","workflowPath":".github/workflows/verify-main.yml","workflowRef":"refs/heads/main"},"provenance":"trusted_ci"}})";

} // namespace

// A record making no claim needs no verifier, no host, and no store. This is why
// the option is not required: an ordinary validation must not depend on a
// prepared toolchain it never reaches for.
TEST(TrustPolicy, DerivesAnUntrustedRecordWithoutAHostOrAStore) {
    auto derived =
        deriveRecord(R"({"recordKind":"raw_run_receipt","trust":{"provenance":"diagnostic_untrusted"}})", {});
    ASSERT_TRUE(derived.has_value()) << (derived ? "" : derived.error().detail);
    EXPECT_EQ(*derived, TrustClass::DiagnosticUntrusted);

    auto absent = deriveRecord(R"({"recordKind":"attempt_plan"})", {});
    ASSERT_TRUE(absent.has_value()) << (absent ? "" : absent.error().detail);
    EXPECT_EQ(*absent, TrustClass::DiagnosticUntrusted);
}

// Naming no host is not permission to skip the check. A claim nothing can
// verify is unavailable, which is a refusal and not a quiet demotion.
TEST(TrustPolicy, RefusesATrustedClaimWhenNoVerifierCouldBeLocated) {
    auto derived = deriveRecord(kTrustedRecord, {});
    ASSERT_FALSE(derived.has_value());
    EXPECT_EQ(derived.error().rejection, TrustRejection::ProvenanceUnavailable);
}

// The bytes a claim is about have to be bytes this repository holds, and the
// two halves of that fail in different places, which is worth stating.
//
// A bundle digest the descriptor rules refuse never reaches the store at all:
// the claim is malformed and the attestation is refused. A subject digest is a
// plain string in the claim, so a form the store cannot address is caught by the
// store, and the reason is that the claim points at nothing rather than that it
// was checked and failed.
TEST(TrustPolicy, RefusesATrustedClaimOverBytesTheStoreCannotAddress) {
    const std::string kRecord(kTrustedRecord);
    const auto kBadBundle = std::string(kRecord).replace(
        kRecord.find("sha256:1111"), std::string_view("sha256:1111").size(), "sha512:1111");
    auto refusedBundle = deriveRecord(kBadBundle, "prepared-tools");
    ASSERT_FALSE(refusedBundle.has_value());
    EXPECT_EQ(refusedBundle.error().rejection, TrustRejection::AttestationRefused);

    const auto kBadSubject = std::string(kRecord).replace(
        kRecord.find("sha256:0307"), std::string_view("sha256:0307").size(), "sha512:0307");
    auto refusedSubject = deriveRecord(kBadSubject, "prepared-tools");
    ASSERT_FALSE(refusedSubject.has_value());
    EXPECT_EQ(refusedSubject.error().rejection, TrustRejection::ProvenanceUnavailable);
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
