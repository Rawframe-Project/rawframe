#include "canonical_json.h"
#include "descriptor.h"
#include "failure.h"
#include "raw_run_receipt.h"
#include "schema_oracle.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

std::filesystem::path repositoryRoot() {
    return std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT);
}

std::filesystem::path fixture(std::string_view relative) {
    return repositoryRoot() / "tools/rf_evidence/tests/fixtures/evidence" / relative;
}

std::string readFixture(std::string_view relative) {
    std::ifstream input(fixture(relative), std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing fixture: " << relative;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

CanonicalValue canonicalFixture(std::string_view relative) {
    auto record = ingestCanonicalBytes(readFixture(relative));
    EXPECT_TRUE(record.has_value()) << relative << ": " << (record ? std::string{} : record.error().detail);
    return record.value_or(CanonicalValue{});
}

constexpr std::string_view kCanonicalRecord = "canonical/raw-run-receipt-v1.canonical.json";

} // namespace

// The anchor. Every rejection case below mutates one thing about a record built
// the same way, so none of them can pass because validation stopped happening.
TEST(RawRunReceipt, AcceptsTheUnmutatedCanonicalRecord) {
    const std::string kBytes = readFixture(kCanonicalRecord);
    auto record = ingestCanonicalBytes(kBytes);
    ASSERT_TRUE(record.has_value()) << (record ? std::string{} : record.error().detail);
    auto summary = validateRawRunReceipt(repositoryRoot(), fixture(kCanonicalRecord), *record, kRawRunReceiptMediaType);
    ASSERT_TRUE(summary.has_value()) << (summary ? std::string{} : summary.error().detail);
    EXPECT_EQ(summary->status, "completed");
    EXPECT_EQ(summary->provenance, "diagnostic_untrusted");
    EXPECT_EQ(summary->metricCount, 2U);
    EXPECT_EQ(summary->attachmentCount, 1U);
}

// The committed canonical bytes are the golden vector. If the serializer ever
// drifts, this is the case that says so before any digest is published.
TEST(RawRunReceipt, ProducesTheCommittedGoldenBytesAndDigest) {
    const std::string kAuthored = readFixture("records/raw-run-receipt-authored.json");
    auto parsed = parseCanonicalSubset(kAuthored);
    ASSERT_TRUE(parsed.has_value()) << (parsed ? std::string{} : parsed.error().detail);
    const std::string kCanonical = serializeCanonical(*parsed);
    EXPECT_EQ(kCanonical, readFixture(kCanonicalRecord));

    auto descriptor = describeBytes(kCanonical, kRawRunReceiptMediaType);
    ASSERT_TRUE(descriptor.has_value());
    auto goldenValue = ingestCanonicalBytes(readFixture("canonical/raw-run-receipt-v1.descriptor.json"));
    ASSERT_TRUE(goldenValue.has_value());
    auto golden = parseDescriptor(*goldenValue);
    ASSERT_TRUE(golden.has_value()) << (golden ? std::string{} : golden.error().detail);
    EXPECT_EQ(descriptor->digest, golden->digest);
    EXPECT_EQ(descriptor->byteLength, golden->byteLength);
    EXPECT_EQ(descriptor->mediaType, golden->mediaType);
}

// The authored fixture is pretty printed, so it is a real record and is not
// canonical. Both halves matter: the first proves canonicalization has work to
// do, the second proves ingest refuses to do that work silently.
TEST(RawRunReceipt, RefusesAuthoredBytesAsAClaimedCanonicalRecord) {
    const std::string kAuthored = readFixture("records/raw-run-receipt-authored.json");
    EXPECT_TRUE(parseCanonicalSubset(kAuthored).has_value());
    auto ingested = ingestCanonicalBytes(kAuthored);
    ASSERT_FALSE(ingested.has_value());
    EXPECT_EQ(ingested.error().rejection, RecordRejection::NoncanonicalBytes);
}

TEST(RawRunReceipt, RejectsARecordCarryingAVerdictMember) {
    const auto kRecord = canonicalFixture("records/reject-verdict-member.json");
    auto status = checkProducerAuthority(kRecord);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
    EXPECT_NE(status.error().detail.find("verdict member"), std::string::npos);
}

TEST(RawRunReceipt, RejectsEveryForbiddenVerdictSpellingAtAnyDepth) {
    for (const std::string_view kName :
         {"pass", "passed", "fail", "failed", "regressed", "accepted", "promoted", "baseline", "verdict"}) {
        const std::string kNested = std::string(R"({"observations":{")") + std::string(kName) + R"(":true}})";
        auto record = parseCanonicalSubset(kNested);
        ASSERT_TRUE(record.has_value()) << kName;
        auto status = checkProducerAuthority(*record);
        EXPECT_FALSE(status.has_value()) << kName << " must not be admitted as a member name";
    }
    auto benign = parseCanonicalSubset(R"({"observations":{"sampleCount":1}})");
    ASSERT_TRUE(benign.has_value());
    EXPECT_TRUE(checkProducerAuthority(*benign).has_value());
}

TEST(RawRunReceipt, RejectsAnUnknownMemberThroughTheSchema) {
    const auto kInstance = fixture("records/reject-unknown-member.json");
    auto status = checkSchema(repositoryRoot(), kInstance);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(RawRunReceipt, RejectsATerminalStatusOutsideTheFiveAcceptedValues) {
    auto status = checkSchema(repositoryRoot(), fixture("records/reject-sixth-status.json"));
    EXPECT_FALSE(status.has_value());
}

// A non-completed status without its typed reason, and a completed status
// carrying one, are both refused. The second direction is the one an
// implementation forgets, and it is how a finished run acquires a reason code.
TEST(RawRunReceipt, BindsTheTypedReasonToNonCompletedStatusInBothDirections) {
    EXPECT_FALSE(checkSchema(repositoryRoot(), fixture("records/reject-noncompleted-without-reason.json")).has_value());
    EXPECT_TRUE(checkSchema(repositoryRoot(), fixture("records/accept-workload-failure.json")).has_value());
}

// A run that failed its workload is still an observation, not a verdict, so it
// validates and reports its own status rather than being refused.
TEST(RawRunReceipt, AcceptsAWorkloadFailureAsAnObservation) {
    const auto kRecord = canonicalFixture("records/accept-workload-failure.json");
    auto summary = validateRawRunReceipt(
        repositoryRoot(), fixture("records/accept-workload-failure.json"), kRecord, kRawRunReceiptMediaType);
    ASSERT_TRUE(summary.has_value()) << (summary ? std::string{} : summary.error().detail);
    EXPECT_EQ(summary->status, "workload_failure");
}

TEST(RawRunReceipt, RejectsAGenerationTheSchemaDoesNotDeclare) {
    EXPECT_FALSE(checkSchema(repositoryRoot(), fixture("records/reject-generation-two.json")).has_value());
}

// Decision 3, driven from each side. Neither the record nor the media type is
// preferred, because a preference order is how one of two cross-checks becomes
// decorative.
TEST(RawRunReceipt, RejectsDisagreementBetweenTheRecordAndTheMediaTypeGeneration) {
    const auto kRecord = canonicalFixture(kCanonicalRecord);
    EXPECT_TRUE(checkGenerationAgreement(kRecord, kRawRunReceiptMediaType).has_value());

    auto status = checkGenerationAgreement(kRecord, "application/vnd.rawframe.evidence.raw-run-receipt.v2+json");
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);

    const auto kSecondGeneration = canonicalFixture("records/reject-generation-two.json");
    auto reversed =
        checkGenerationAgreement(kSecondGeneration, "application/vnd.rawframe.evidence.raw-run-receipt.v2+json");
    ASSERT_FALSE(reversed.has_value());
    EXPECT_EQ(reversed.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(RawRunReceipt, RejectsAMediaTypeThatNamesNoGeneration) {
    const auto kRecord = canonicalFixture(kCanonicalRecord);
    for (const std::string_view kMediaType : {"application/json",
                                              "application/vnd.rawframe.evidence.raw-run-receipt+json",
                                              "application/vnd.rawframe.evidence.raw-run-receipt.vx+json",
                                              "application/vnd.rawframe.evidence.raw-run-receipt.v1"}) {
        auto status = checkGenerationAgreement(kRecord, kMediaType);
        EXPECT_FALSE(status.has_value()) << kMediaType;
    }
}

// An oracle that could not run, could not resolve, or answered unrecognisably
// is a failed validation and never a skipped one.
TEST(RawRunReceipt, TreatsAnUnusableOracleAsAFailureRatherThanASkip) {
    auto status = checkSchema(repositoryRoot(), fixture("records/does-not-exist.json"));
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

// Decision 2 rests on the oracle failing closed when a cross-document reference
// cannot be resolved offline, rather than quietly validating the part it can
// see. Withholding the import is the only way to observe that, so the property
// is held by a case instead of by a probe that ran once.
TEST(RawRunReceipt, FailsClosedWhenTheImportedSchemaIsWithheld) {
    const std::filesystem::path kSchema = repositoryRoot() / kRawRunReceiptSchemaPath;
    const std::filesystem::path kInstance = fixture(kCanonicalRecord);
    const std::array<std::filesystem::path, 1> kImports{repositoryRoot() / kEvidenceCommonSchemaPath};

    auto resolved = validateJsonShape(repositoryRoot(), kSchema, kInstance, kImports);
    EXPECT_TRUE(resolved.has_value()) << (resolved ? std::string{} : resolved.error().message);

    auto withheld = validateJsonShape(repositoryRoot(), kSchema, kInstance);
    ASSERT_FALSE(withheld.has_value());
    // Distinct from a shape failure: the record is valid, and the oracle is
    // saying it could not answer rather than that the answer was no.
    EXPECT_EQ(withheld.error().code, FailureCode::VerificationFailed);
}

TEST(RawRunReceipt, SummarizesOnlyObservationsAndNeverAnOutcome) {
    const auto kRecord = canonicalFixture(kCanonicalRecord);
    auto summary = summarizeRawRunReceipt(kRecord);
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(summary->runId, "6f1c2d3e-4a5b-4c7d-8e9f-0a1b2c3d4e5f");
    EXPECT_EQ(summary->lifecycleEventCount, 1U);

    auto descriptor = describeBytes(readFixture(kCanonicalRecord), kRawRunReceiptMediaType);
    ASSERT_TRUE(descriptor.has_value());
    const std::string kOutput = buildValidateOutput(*descriptor, *summary);
    for (const std::string_view kWord : {"\"pass\"", "\"fail\"", "\"regressed\"", "\"baseline\"", "\"promoted\""}) {
        EXPECT_EQ(kOutput.find(kWord), std::string::npos) << "output must not report an outcome: " << kWord;
    }
    EXPECT_NE(kOutput.find("\"ok\":true"), std::string::npos);
}

// Operation output is emitted through this Task's own serializer, so it is
// canonical too. A report that is not itself canonical would be a second JSON
// convention inside the component that exists to have one.
TEST(RawRunReceipt, EmitsCanonicalBytesForItsOwnOutput) {
    const auto kRecord = canonicalFixture(kCanonicalRecord);
    auto summary = summarizeRawRunReceipt(kRecord);
    ASSERT_TRUE(summary.has_value());
    auto descriptor = describeBytes(readFixture(kCanonicalRecord), kRawRunReceiptMediaType);
    ASSERT_TRUE(descriptor.has_value());
    EXPECT_TRUE(ingestCanonicalBytes(buildValidateOutput(*descriptor, *summary)).has_value());
    EXPECT_TRUE(ingestCanonicalBytes(buildCanonicalizeOutput(*descriptor, *summary)).has_value());
    EXPECT_TRUE(ingestCanonicalBytes(buildRejectionOutput(RecordFailure{RecordRejection::NoncanonicalBytes, "detail"}))
                    .has_value());
}

TEST(RawRunReceipt, NamesEveryRejectionKind) {
    EXPECT_STREQ(recordRejectionName(RecordRejection::MalformedInput), "malformed_input");
    EXPECT_STREQ(recordRejectionName(RecordRejection::NoncanonicalBytes), "noncanonical_bytes");
    EXPECT_STREQ(recordRejectionName(RecordRejection::SchemaInvalid), "schema_invalid");
    EXPECT_STREQ(recordRejectionName(RecordRejection::DescriptorMismatch), "descriptor_mismatch");
    EXPECT_STREQ(recordRejectionName(RecordRejection::LimitExceeded), "limit_exceeded");
}

} // namespace rawframe::tool::evidence
