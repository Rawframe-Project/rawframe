#include "canonical_json.h"
#include "trust_policy.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
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
// The repository is in the `owner/name` shorthand the schema constrains a claim
// to. It said otherwise until the first genuine bundle showed that the URL
// spelling could never verify, and this fixture had not noticed because the case
// it serves is refused before the source is ever compared.
constexpr std::string_view kTrustedRecord =
    R"({"recordKind":"raw_run_receipt","trust":{"attestation":{"builderId":"https://github.com/Rawframe-Project/rawframe/.github/workflows/trusted-verification.yml@refs/heads/main","bundle":{"byteLength":11101,"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"},"runAttempt":1,"runId":30535694786,"sourceCommit":"dc9563e75e1144f5e296d9cb0d883c0fe2ca12ac","sourceRef":"refs/heads/main","sourceRepository":"Rawframe-Project/rawframe","subjectDigest":"sha256:03074dece2e6c4a99f66eae62f4f01b96343847e3300f8ac717268ab77de77ff","subjectName":"linux-x86_64-reports.tar","workflowPath":".github/workflows/verify-main.yml","workflowRef":"refs/heads/main"},"provenance":"trusted_ci"}})";

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

// The replay rule, over the genuine protected-ref pair.
//
// It is here rather than beside the other attestation cases because it is the
// one requirement a signature cannot answer: the statement being replayed is
// correctly signed, correctly issued, and names the protected producer, and it
// is refused anyway because that run identity has already been admitted for
// different bytes. Nothing short of the real bundle proves that, since the check
// runs only after the other seven requirements have already passed.
namespace {

const std::filesystem::path& attestationFixtureRoot() {
    static const std::filesystem::path kRoot =
        std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT) / "tools/rf_evidence/tests/fixtures/evidence/attestations";
    return kRoot;
}

constexpr std::string_view kMainBundleFixture = "main-run-30554540067.sigstore.json";
constexpr std::string_view kMainSubjectFixture = "main-run-30554540067-subject.tar";
constexpr std::string_view kMainSubjectDigest =
    "sha256:e2e03a33c123de0fb4527afe2a4a6d48573181d51aca578213cd8e297df81e9e";
constexpr std::int64_t kMainRunId = 30554540067;
constexpr std::int64_t kMainRunAttempt = 1;

// The trust block the genuine run would carry, with the bundle descriptor
// measured from the fixture rather than written down. A transcribed length or
// digest would make this test fail for the wrong reason the day the fixture is
// replaced, and the descriptor rules are proven elsewhere.
std::string genuineTrustBlock() {
    const auto kBundle = attestationFixtureRoot() / std::filesystem::path(std::string(kMainBundleFixture));
    std::ifstream input(kBundle, std::ios::binary);
    EXPECT_TRUE(input.is_open()) << kBundle.generic_string();
    const std::string kBytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    auto described = describeBytes(kBytes, kSigstoreBundleMediaType);
    EXPECT_TRUE(described.has_value());
    const Descriptor kDescriptor = described.value_or(Descriptor{});

    return std::string(R"({"attestation":{"builderId":")") + std::string(kTrustedCertificateIdentity) +
           R"(","bundle":{"byteLength":)" + std::to_string(kDescriptor.byteLength) + R"(,"digest":")" +
           kDescriptor.digest + R"(","mediaType":")" + std::string(kSigstoreBundleMediaType) + R"("},"runAttempt":)" +
           std::to_string(kMainRunAttempt) + R"(,"runId":)" + std::to_string(kMainRunId) +
           R"(,"sourceCommit":"8ff564495b0818d6ebcd7abcfdae1d5c44c2d38e","sourceRef":")" +
           std::string(kTrustedProtectedRef) + R"(","sourceRepository":")" + std::string(kTrustedSourceRepositoryPath) +
           R"(","subjectDigest":")" + std::string(kMainSubjectDigest) +
           R"(","subjectName":"linux-x86_64-reports.tar","workflowPath":")" + std::string(kTrustedEntryWorkflowPath) +
           R"(","workflowRef":")" + std::string(kTrustedProtectedRef) + R"("},"provenance":"trusted_ci"})";
}

AttestationInputs genuineInputs() {
    const auto kCosignRoot = std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT) / "out" / "prepared" /
                             RAWFRAME_TEST_HOST_ID / "tools" / "cosign";
    return AttestationInputs{
        .bundlePath = attestationFixtureRoot() / std::filesystem::path(std::string(kMainBundleFixture)),
        .subjectPath = attestationFixtureRoot() / std::filesystem::path(std::string(kMainSubjectFixture)),
#ifdef _WIN32
        .cosign = kCosignRoot / "bin" / "cosign.exe",
#else
        .cosign = kCosignRoot / "bin" / "cosign",
#endif
        .trustedRoot = kCosignRoot / "share" / "trusted_root.json",
    };
}

TrustResult<TrustClass> deriveGenuine(std::span<const AdmittedRun> admitted) {
    auto value = ingestCanonicalBytes(genuineTrustBlock());
    EXPECT_TRUE(value.has_value()) << "the trust block built here must itself be canonical";
    if (!value) {
        return std::unexpected(TrustFailure{TrustRejection::MalformedTrustBlock, "fixture is not canonical"});
    }
    return deriveTrustClass(*value, genuineInputs(), admitted);
}

} // namespace

TEST(TrustPolicy, RefusesAGenuineAttestationWhoseRunIdentityWasAdmittedForOtherBytes) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(genuineInputs().cosign, error) || error) {
        // Named out loud for the same reason the attestation case names it: a
        // green result that quietly took this branch would read as a proven
        // replay refusal, and it is not one.
        RecordProperty("verifier", "absent");
        GTEST_LOG_(INFO) << "the locked verifier is absent, so the replay rule was not reached here";
        auto unavailable = deriveGenuine({});
        ASSERT_FALSE(unavailable.has_value());
        EXPECT_EQ(unavailable.error().rejection, TrustRejection::AttestationRefused);
        return;
    }
    RecordProperty("verifier", "present");

    // The same statement, admitted three ways. It is trusted with an empty
    // ledger, still trusted when the ledger already holds this run over these
    // same bytes, because re-deriving one admission is not a second one, and
    // refused only when the run identity is already spoken for by a different
    // subject.
    auto first = deriveGenuine({});
    ASSERT_TRUE(first.has_value()) << (first ? "" : first.error().detail);
    EXPECT_EQ(*first, TrustClass::TrustedCi);

    const std::array<AdmittedRun, 1> kSameSubject{
        AdmittedRun{kMainRunId, kMainRunAttempt, std::string(kMainSubjectDigest)}};
    auto repeated = deriveGenuine(kSameSubject);
    ASSERT_TRUE(repeated.has_value()) << (repeated ? "" : repeated.error().detail);
    EXPECT_EQ(*repeated, TrustClass::TrustedCi);

    const std::array<AdmittedRun, 1> kOtherSubject{
        AdmittedRun{kMainRunId, kMainRunAttempt, "sha256:" + std::string(64U, 'a')}};
    auto replayed = deriveGenuine(kOtherSubject);
    ASSERT_FALSE(replayed.has_value());
    EXPECT_EQ(replayed.error().rejection, TrustRejection::AttestationRefused);
    EXPECT_NE(replayed.error().detail.find("run_identity_replayed"), std::string::npos)
        << "the refusal must name the replay rather than report a generic failure: " << replayed.error().detail;

    // A different attempt of the same run is a different run identity, so it is
    // not a replay. The distinction matters because a rerun is ordinary.
    const std::array<AdmittedRun, 1> kOtherAttempt{
        AdmittedRun{kMainRunId, kMainRunAttempt + 1, "sha256:" + std::string(64U, 'a')}};
    auto other = deriveGenuine(kOtherAttempt);
    ASSERT_TRUE(other.has_value()) << (other ? "" : other.error().detail);
    EXPECT_EQ(*other, TrustClass::TrustedCi);
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
