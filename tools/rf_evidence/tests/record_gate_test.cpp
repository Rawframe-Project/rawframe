#include "canonical_json.h"
#include "descriptor.h"
#include "evidence_set.h"
#include "raw_run_receipt.h"
#include "record_gate.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

std::filesystem::path repositoryRoot() {
    return std::filesystem::path(RAWFRAME_TEST_REPOSITORY_ROOT);
}

std::filesystem::path fixture(std::string_view relative) {
    return repositoryRoot() / "tools/rf_evidence/tests/fixtures/evidence" / relative;
}

CanonicalValue canonicalFixture(std::string_view relative) {
    std::ifstream input(fixture(relative), std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing fixture: " << relative;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    auto record = ingestCanonicalBytes(buffer.str());
    EXPECT_TRUE(record.has_value()) << relative;
    return record.value_or(CanonicalValue{});
}

constexpr std::string_view kReceipt = "canonical/raw-run-receipt-v1.canonical.json";
constexpr std::string_view kPlan = "plans/complete.json";

CanonicalValue objectWith(std::vector<CanonicalValue::Member> members) {
    return CanonicalValue::makeObject(std::move(members));
}

} // namespace

// The anchor for the authority rule: a real record carries no verdict member,
// so every rejection below is about the member that was added and not about the
// walk refusing everything it is handed.
TEST(RecordGate, AcceptsARecordThatClaimsNoOutcome) {
    EXPECT_TRUE(checkProducerAuthority(canonicalFixture(kReceipt)).has_value());
    EXPECT_TRUE(checkProducerAuthority(canonicalFixture(kPlan)).has_value());
}

TEST(RecordGate, RejectsAVerdictMemberAtTheTopLevel) {
    auto status = checkProducerAuthority(objectWith({{"verdict", CanonicalValue::makeString("pass")}}));
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

// The walk descends through arrays as well as objects. A verdict buried in the
// second element of a list is the same claim made less visibly.
TEST(RecordGate, RejectsAVerdictMemberNestedInsideAnArray) {
    std::vector<CanonicalValue> elements;
    elements.push_back(CanonicalValue::makeInteger(1));
    elements.push_back(objectWith({{"nested", objectWith({{"passed", CanonicalValue::makeBoolean(true)}})}}));
    auto status =
        checkProducerAuthority(objectWith({{"observations", CanonicalValue::makeArray(std::move(elements))}}));
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

// The kind is read from the record's own bytes. A caller never supplies it, so
// a record cannot be relabelled by the command line that reads it.
TEST(RecordGate, ReadsTheRecordKindFromTheBytesRatherThanFromTheCaller) {
    auto kind = readRecordKind(canonicalFixture(kReceipt));
    ASSERT_TRUE(kind.has_value());
    EXPECT_EQ(*kind, kRawRunReceiptRecordKind);

    auto planKind = readRecordKind(canonicalFixture(kPlan));
    ASSERT_TRUE(planKind.has_value());
    EXPECT_EQ(*planKind, kAttemptPlanRecordKind);
}

TEST(RecordGate, RejectsARecordThatDeclaresADifferentKindThanRequired) {
    auto status = checkRecordKind(canonicalFixture(kPlan), kRawRunReceiptRecordKind);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);
}

TEST(RecordGate, RejectsARecordThatDeclaresNoKindAtAll) {
    auto status =
        checkRecordKind(objectWith({{"schemaVersion", CanonicalValue::makeInteger(1)}}), kRawRunReceiptRecordKind);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

// The generation in the bytes and the generation in the media type are two
// independent statements. Neither is preferred, because a preference order is
// how one of two cross-checks becomes decorative.
TEST(RecordGate, AcceptsAGenerationBothStatementsAgreeOn) {
    EXPECT_TRUE(checkGenerationMatches(canonicalFixture(kReceipt), kRawRunReceiptMediaType, 1).has_value());
    EXPECT_TRUE(checkGenerationMatches(canonicalFixture(kPlan), kAttemptPlanMediaType, 1).has_value());
}

TEST(RecordGate, RejectsDisagreementBetweenTheRecordAndItsMediaType) {
    auto status = checkGenerationMatches(
        canonicalFixture(kReceipt), "application/vnd.rawframe.evidence.raw-run-receipt.v2+json", 1);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);
}

TEST(RecordGate, RejectsAMediaTypeThatNamesNoGeneration) {
    auto status =
        checkGenerationMatches(canonicalFixture(kReceipt), "application/vnd.rawframe.evidence.raw-run-receipt+json", 1);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::DescriptorMismatch);
}

// Both statements can agree on a generation this tool does not implement. That
// is still a refusal, because agreement is not the same as support.
TEST(RecordGate, RejectsAGenerationThisToolDoesNotImplement) {
    auto status = checkGenerationMatches(canonicalFixture(kReceipt), kRawRunReceiptMediaType, 2);
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

// The point of the extraction: validation runs against the schema it is handed,
// not against one fixed record kind. Each record satisfies its own schema and
// fails the other's, which is what proves the gate is generic rather than a
// receipt check wearing a wider signature.
TEST(RecordGate, ValidatesAgainstTheSchemaItIsHandedRatherThanAFixedOne) {
    EXPECT_TRUE(validateAgainstSchema(repositoryRoot(), kRawRunReceiptSchemaPath, fixture(kReceipt)).has_value());
    EXPECT_TRUE(validateAgainstSchema(repositoryRoot(), kAttemptPlanSchemaPath, fixture(kPlan)).has_value());

    EXPECT_FALSE(validateAgainstSchema(repositoryRoot(), kAttemptPlanSchemaPath, fixture(kReceipt)).has_value());
    EXPECT_FALSE(validateAgainstSchema(repositoryRoot(), kRawRunReceiptSchemaPath, fixture(kPlan)).has_value());
}

// A schema that is not there is a validation that did not happen. It is
// reported as a failure and never as a quietly skipped check.
TEST(RecordGate, TreatsAMissingSchemaAsAFailureRatherThanASkip) {
    auto status = validateAgainstSchema(repositoryRoot(), "schemas/no-such-schema-v1.schema.json", fixture(kReceipt));
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().rejection, RecordRejection::SchemaInvalid);
}

} // namespace rawframe::tool::evidence
