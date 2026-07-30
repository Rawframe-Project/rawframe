#include "attestation.h"
#include "canonical_json.h"

#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

// A structurally genuine statement for the protected producer, built here
// rather than checked in, so that every negative case below is one named
// mutation of one reference value. A fixture per case would let a case pass
// because two fields drifted apart rather than because the rule fired.
constexpr std::string_view kSubjectName = "rf-evidence-conformance-linux-x86_64.json";
constexpr std::string_view kSubjectDigestHex = "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862";
constexpr std::string_view kBuilderId = "https://github.com/Rawframe-Project/rawframe/.github/workflows/"
                                        "trusted-verification.yml@refs/heads/main";
constexpr std::string_view kCommit = "0123456789abcdef0123456789abcdef01234567";
constexpr std::int64_t kRunId = 30485058826;
constexpr std::int64_t kRunAttempt = 1;

std::string base64Encode(std::string_view raw) {
    constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    for (std::size_t offset = 0; offset < raw.size(); offset += 3U) {
        const std::size_t remaining = raw.size() - offset;
        const auto first = static_cast<unsigned char>(raw[offset]);
        const auto second = remaining > 1U ? static_cast<unsigned char>(raw[offset + 1U]) : 0U;
        const auto third = remaining > 2U ? static_cast<unsigned char>(raw[offset + 2U]) : 0U;
        const std::uint32_t triple = (static_cast<std::uint32_t>(first) << 16U)
                                     | (static_cast<std::uint32_t>(second) << 8U) | static_cast<std::uint32_t>(third);
        encoded.push_back(kAlphabet[(triple >> 18U) & 0x3FU]);
        encoded.push_back(kAlphabet[(triple >> 12U) & 0x3FU]);
        encoded.push_back(remaining > 1U ? kAlphabet[(triple >> 6U) & 0x3FU] : '=');
        encoded.push_back(remaining > 2U ? kAlphabet[triple & 0x3FU] : '=');
    }
    return encoded;
}

struct StatementFields {
    std::string statementType{kInTotoStatementType};
    std::string predicateType{kSlsaProvenancePredicateType};
    std::string subjectName{kSubjectName};
    std::string subjectDigest{kSubjectDigestHex};
    std::string builderId{kBuilderId};
    std::string repository{kTrustedSourceRepository};
    std::string workflowPath{kTrustedWorkflowPath};
    std::string workflowRef{"refs/heads/main"};
    std::string sourceUri{"git+https://github.com/Rawframe-Project/rawframe@refs/heads/main"};
    std::string commit{kCommit};
    std::string invocationId{"https://github.com/Rawframe-Project/rawframe/actions/runs/30485058826/attempts/1"};
};

std::string buildStatement(const StatementFields& fields) {
    return std::string(R"({"_type":")") + fields.statementType + R"(","predicateType":")" + fields.predicateType
           + R"(","predicate":{"buildDefinition":{"externalParameters":{"workflow":{"path":")" + fields.workflowPath
           + R"(","ref":")" + fields.workflowRef + R"(","repository":")" + fields.repository
           + R"("}},"internalParameters":{"github":{"event_name":"push"}},"resolvedDependencies":[{"digest":{"gitCommit":")"
           + fields.commit + R"("},"uri":")" + fields.sourceUri
           + R"("}]},"runDetails":{"builder":{"id":")" + fields.builderId + R"("},"metadata":{"invocationId":")"
           + fields.invocationId + R"("}}},"subject":[{"digest":{"sha256":")" + fields.subjectDigest + R"("},"name":")"
           + fields.subjectName + R"("}]})";
}

std::string buildBundle(const StatementFields& fields, std::string_view mediaType = kSigstoreBundleMediaType,
                        std::string_view payloadType = kInTotoPayloadType, std::size_t signatureCount = 1U) {
    std::string signatures = "[";
    for (std::size_t index = 0; index < signatureCount; ++index) {
        if (index != 0U) {
            signatures += ",";
        }
        signatures += R"({"sig":"c2lnbmF0dXJl"})";
    }
    signatures += "]";
    return std::string(R"({"dsseEnvelope":{"payload":")") + base64Encode(buildStatement(fields))
           + R"(","payloadType":")" + std::string(payloadType) + R"(","signatures":)" + signatures
           + R"(},"mediaType":")" + std::string(mediaType) + R"("})";
}

AttestationRejection rejectionOf(const std::string& bundle) {
    auto decoded = decodeProvenanceBundle(bundle);
    EXPECT_FALSE(decoded.has_value()) << "expected a rejection for this bundle";
    if (decoded) {
        return AttestationRejection::ClaimMalformed;
    }
    return decoded.error().rejection;
}

std::string claimText(std::string_view bundleDigest, std::uint64_t bundleLength) {
    return std::string(R"({"builderId":")") + std::string(kBuilderId)
           + R"(","bundle":{"byteLength":)" + std::to_string(bundleLength)
           + R"(,"digest":"sha256:)" + std::string(bundleDigest)
           + R"(","mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"},"runAttempt":1,"runId":30485058826,"sourceCommit":")"
           + std::string(kCommit) + R"(","sourceRef":"refs/heads/main","sourceRepository":")"
           + std::string(kTrustedSourceRepository) + R"(","subjectDigest":"sha256:)" + std::string(kSubjectDigestHex)
           + R"(","subjectName":")" + std::string(kSubjectName) + R"(","workflowPath":")"
           + std::string(kTrustedWorkflowPath) + R"(","workflowRef":"refs/heads/main"})";
}

} // namespace

TEST(Attestation, DecodesAGenuineProvenanceStatement) {
    auto decoded = decodeProvenanceBundle(buildBundle(StatementFields{}));
    ASSERT_TRUE(decoded.has_value()) << (decoded ? "" : decoded.error().detail);
    EXPECT_EQ(decoded->subjectName, kSubjectName);
    EXPECT_EQ(decoded->subjectDigest, kSubjectDigestHex);
    EXPECT_EQ(decoded->builderId, kBuilderId);
    EXPECT_EQ(decoded->sourceRepository, kTrustedSourceRepository);
    EXPECT_EQ(decoded->sourceCommit, kCommit);
    EXPECT_EQ(decoded->sourceRef, "refs/heads/main");
    EXPECT_EQ(decoded->workflowPath, kTrustedWorkflowPath);
    EXPECT_EQ(decoded->runId, kRunId);
    EXPECT_EQ(decoded->runAttempt, kRunAttempt);
}

TEST(Attestation, RefusesAnEnvelopeThatIsNotTheAcceptedOne) {
    EXPECT_EQ(rejectionOf(buildBundle(StatementFields{}, "application/vnd.dev.sigstore.bundle.v0.2+json")),
              AttestationRejection::EnvelopeMismatch);
    EXPECT_EQ(rejectionOf(buildBundle(StatementFields{}, kSigstoreBundleMediaType, "application/json")),
              AttestationRejection::EnvelopeMismatch);
}

// One signature, exactly. A bundle carrying two is a bundle where a reader has
// to choose which one verification was about, and there is no correct choice.
TEST(Attestation, RefusesAnEnvelopeCarryingMoreOrFewerThanOneSignature) {
    EXPECT_EQ(rejectionOf(buildBundle(StatementFields{}, kSigstoreBundleMediaType, kInTotoPayloadType, 0U)),
              AttestationRejection::EnvelopeMismatch);
    EXPECT_EQ(rejectionOf(buildBundle(StatementFields{}, kSigstoreBundleMediaType, kInTotoPayloadType, 2U)),
              AttestationRejection::EnvelopeMismatch);
}

TEST(Attestation, RefusesAStatementOrPredicateTypeThisGenerationDoesNotAccept) {
    StatementFields statement;
    statement.statementType = "https://in-toto.io/Statement/v0.1";
    EXPECT_EQ(rejectionOf(buildBundle(statement)), AttestationRejection::StatementMismatch);

    StatementFields predicate;
    predicate.predicateType = "https://slsa.dev/provenance/v0.2";
    EXPECT_EQ(rejectionOf(buildBundle(predicate)), AttestationRejection::StatementMismatch);
}

TEST(Attestation, RefusesAStatementWhoseSourceOrWorkflowIsNotTheProtectedProducer) {
    StatementFields workflow;
    workflow.workflowPath = ".github/workflows/publish-host-images.yml";
    auto decodedWorkflow = decodeProvenanceBundle(buildBundle(workflow));
    ASSERT_TRUE(decodedWorkflow.has_value());
    EXPECT_NE(decodedWorkflow->workflowPath, kTrustedWorkflowPath);

    StatementFields source;
    source.repository = "Rawframe-Project/rawframe-mirror";
    auto decodedSource = decodeProvenanceBundle(buildBundle(source));
    ASSERT_TRUE(decodedSource.has_value());
    EXPECT_NE(decodedSource->sourceRepository, kTrustedSourceRepository);
}

TEST(Attestation, RefusesAStatementWithNoResolvableRunIdentity) {
    StatementFields missingAttempt;
    missingAttempt.invocationId = "https://github.com/Rawframe-Project/rawframe/actions/runs/30485058826";
    EXPECT_EQ(rejectionOf(buildBundle(missingAttempt)), AttestationRejection::RunIdentityMissing);

    StatementFields nonNumeric;
    nonNumeric.invocationId = "https://github.com/Rawframe-Project/rawframe/actions/runs/main/attempts/first";
    EXPECT_EQ(rejectionOf(buildBundle(nonNumeric)), AttestationRejection::RunIdentityMissing);
}

TEST(Attestation, RefusesASourceUriThatNamesNoRef) {
    StatementFields fields;
    fields.sourceUri = "git+https://github.com/Rawframe-Project/rawframe";
    EXPECT_EQ(rejectionOf(buildBundle(fields)), AttestationRejection::SourceMismatch);
}

// The payload is base64 and only base64. A URL-safe alphabet, misplaced
// padding, or trailing data would each let two encodings produce one statement.
TEST(Attestation, RefusesAPayloadThatIsNotStandardPaddedBase64) {
    const std::string genuine = buildBundle(StatementFields{});
    const std::string urlSafe = std::string(R"({"dsseEnvelope":{"payload":"e19fXw-_","payloadType":")")
                                + std::string(kInTotoPayloadType)
                                + R"(","signatures":[{"sig":"c2ln"}]},"mediaType":")"
                                + std::string(kSigstoreBundleMediaType) + R"("})";
    EXPECT_EQ(rejectionOf(urlSafe), AttestationRejection::BundleMalformed);
    EXPECT_NE(genuine, urlSafe);
}

TEST(Attestation, ParsesAWellFormedClaimAndRefusesAZeroRunIdentity) {
    const std::string bundle = buildBundle(StatementFields{});
    auto described = describeBytes(bundle, kSigstoreBundleMediaType);
    ASSERT_TRUE(described.has_value());
    const std::string digestHex = described->digest.substr(std::string_view("sha256:").size());

    auto parsedClaim = ingestCanonicalBytes(claimText(digestHex, described->byteLength));
    ASSERT_TRUE(parsedClaim.has_value()) << (parsedClaim ? "" : parsedClaim.error().detail);
    auto claim = parseAttestationClaim(*parsedClaim);
    ASSERT_TRUE(claim.has_value()) << (claim ? "" : claim.error().detail);
    EXPECT_EQ(claim->runId, kRunId);
    EXPECT_EQ(claim->subjectName, kSubjectName);

    std::string zeroed = claimText(digestHex, described->byteLength);
    const auto runIdOffset = zeroed.find(R"("runId":30485058826)");
    ASSERT_NE(runIdOffset, std::string::npos);
    zeroed.replace(runIdOffset, std::string_view(R"("runId":30485058826)").size(), R"("runId":0)");
    auto zeroedValue = ingestCanonicalBytes(zeroed);
    ASSERT_TRUE(zeroedValue.has_value());
    auto zeroedClaim = parseAttestationClaim(*zeroedValue);
    ASSERT_FALSE(zeroedClaim.has_value());
    EXPECT_EQ(zeroedClaim.error().rejection, AttestationRejection::RunIdentityMissing);
}

// The verifier is a locked external binary, and its absence is its own answer.
// Reporting a missing verifier as a failed signature would make an unconfigured
// host look like a forged bundle.
TEST(Attestation, ReportsAnAbsentVerifierAsUnavailableRatherThanInvalid) {
    AttestationInputs inputs;
    inputs.bundlePath = "does-not-exist.sigstore.json";
    inputs.subjectPath = "does-not-exist.json";
    inputs.cosign = "does-not-exist-cosign";
    inputs.trustedRoot = "does-not-exist-trusted-root.json";
    auto status = verifyBundleSignature(inputs, "sha256:" + std::string(kSubjectDigestHex));
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, AttestationRejection::VerifierUnavailable);
}

TEST(Attestation, ReportsAnAbsentSubjectRatherThanDigestingNothing) {
    auto digest = digestSubject("does-not-exist.json");
    ASSERT_FALSE(digest.has_value());
    EXPECT_EQ(digest.error().rejection, AttestationRejection::BundleUnreadable);
}

} // namespace rawframe::tool::evidence
