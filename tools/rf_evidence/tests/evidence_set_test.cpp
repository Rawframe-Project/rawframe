#include "blob_store.h"
#include "canonical_json.h"
#include "evidence_set.h"
#include "record_gate.h"

#include <algorithm>
#include <cstdint>
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

std::filesystem::path fixtureRoot() {
    return repositoryRoot() / "tools/rf_evidence/tests/fixtures/evidence";
}

std::filesystem::path planPath(std::string_view name) {
    return fixtureRoot() / "plans" / (std::string(name) + ".json");
}

std::string readAllBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing fixture: " << path.generic_string();
    std::ostringstream content;
    content << input.rdbuf();
    return content.str();
}

// A store holding every receipt the fixture plans reference. Each case builds
// its own, so no case can pass because of what another one stored.
// The leaf is derived from the running case's own name rather than from a
// counter. Each case is discovered as its own CTest test and so runs in its own
// process, where a per-process counter would hand every case the same directory
// and let them delete each other's store under parallel execution. It is
// shortened to a hash because the store appends two more path components and
// the case names here are long enough to exceed the Windows path limit.
BlobStore populatedStore() {
    const auto* kInfo = ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string kName =
        kInfo == nullptr ? std::string{"unknown"} : std::string(kInfo->test_suite_name()) + "." + kInfo->name();
    std::uint32_t leaf = 2166136261U;
    for (const char kCharacter : kName) {
        leaf = (leaf ^ static_cast<unsigned char>(kCharacter)) * 16777619U;
    }
    std::string label(8, '0');
    for (std::size_t index = 0; index < 8; ++index) {
        label[7 - index] = "0123456789abcdef"[(leaf >> (index * 4)) & 0xFU];
    }
    const std::filesystem::path kRoot =
        std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "es" / label / "blobs" / "sha256";
    std::filesystem::remove_all(kRoot.parent_path().parent_path());
    std::filesystem::create_directories(kRoot);
    BlobStore store(kRoot);
    for (const auto& kEntry : std::filesystem::directory_iterator(fixtureRoot() / "receipts")) {
        const auto kStored = store.put(kEntry.path());
        EXPECT_TRUE(kStored.has_value()) << kEntry.path().generic_string();
    }
    return store;
}

// Parses a fixture plan and asserts nothing about the outcome, so that both the
// accepting and the rejecting cases can use it.
RecordResult<AttemptPlan> parsePlan(std::string_view name) {
    const auto kPath = planPath(name);
    auto record = ingestCanonicalBytes(readAllBytes(kPath));
    EXPECT_TRUE(record.has_value()) << name;
    if (!record) {
        return std::unexpected(RecordFailure{RecordRejection::MalformedInput, "fixture did not parse"});
    }
    return parseAttemptPlan(repositoryRoot(), kPath, *record);
}

constexpr std::string_view kSetId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

RecordResult<CanonicalValue> assemble(std::string_view planName) {
    auto plan = parsePlan(planName);
    if (!plan) {
        return std::unexpected(plan.error());
    }
    return assembleEvidenceSet(populatedStore(), *plan, kSetId);
}

std::vector<std::string> eligibleIdentities(const CanonicalValue& set) {
    std::vector<std::string> identities;
    const auto* kEligible = set.find("eligibleAttemptIds");
    EXPECT_NE(kEligible, nullptr);
    if (kEligible == nullptr) {
        return identities;
    }
    for (const auto& kEntry : kEligible->elements()) {
        identities.push_back(kEntry.text());
    }
    return identities;
}

std::string statusOf(const CanonicalValue& set, std::string_view attemptId) {
    const auto* kAttempts = set.find("attempts");
    EXPECT_NE(kAttempts, nullptr);
    if (kAttempts == nullptr) {
        return {};
    }
    for (const auto& kAttempt : kAttempts->elements()) {
        const auto* kIdentity = kAttempt.find("attemptId");
        if (kIdentity != nullptr && kIdentity->text() == attemptId) {
            const auto* kStatus = kAttempt.find("status");
            return kStatus == nullptr ? std::string{} : kStatus->text();
        }
    }
    return {};
}

} // namespace

// The anchor. Every rejection case below changes exactly one thing about a plan
// built the same way, so none of them can pass because assembly stopped
// happening at all.
TEST(EvidenceSet, AcceptsACompletePlanAndMarksEveryAttemptEligible) {
    auto set = assemble("complete");
    ASSERT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    EXPECT_EQ(eligibleIdentities(*set).size(), 5U);
    const auto* kSchedule = set->find("schedule");
    ASSERT_NE(kSchedule, nullptr);
    EXPECT_EQ(kSchedule->find("attemptCount")->integer(), 5);
}

// The ledger reports what a producer observed. If it could carry a verdict
// member it would be reporting whether that observation was acceptable, which
// belongs to the evaluator and to no record this tool writes.
TEST(EvidenceSet, EmitsNoVerdictMemberAnywhereInTheAssembledSet) {
    auto set = assemble("complete");
    ASSERT_TRUE(set.has_value());
    EXPECT_TRUE(checkProducerAuthority(*set).has_value());
    EXPECT_EQ(set->find("trust")->find("provenance")->text(), "diagnostic_untrusted");
}

// The plan's own declared count is what makes a dropped attempt visible. A list
// that contradicts it is the shape a cherry-picked ledger takes.
TEST(EvidenceSet, RejectsAPlanThatDeclaresMoreAttemptsThanItLists) {
    auto set = assemble("count-mismatch");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

// A hole in the ordinals is an attempt nobody accounted for, whatever the count
// says.
TEST(EvidenceSet, RejectsAPlanWhoseAttemptOrdinalsSkipAValue) {
    auto set = assemble("ordinal-gap");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(EvidenceSet, RejectsTwoAttemptsClaimingOneIdentity) {
    auto set = assemble("duplicate-identity");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

// Three good runs presented as the whole of a five-run schedule. The counts are
// internally consistent; only the untouched repetitions expose it.
TEST(EvidenceSet, RejectsAFavorableSubsetOfAWiderSchedule) {
    auto set = assemble("favorable-subset");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(EvidenceSet, RejectsASupersedesLinkThatLeavesThePlan) {
    auto set = assemble("supersedes-outside");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

// A loop is how a superseded attempt could be made to disappear from the
// eligible set without ever being removed from the plan.
TEST(EvidenceSet, RejectsASupersedesChainThatLoops) {
    auto set = assemble("supersedes-loop");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

// Compatibility is copied from the receipts and compared. It is never filled
// in, preferred, or reconciled, so two receipts that disagree fail the whole
// assembly rather than producing a set bound to one of them.
TEST(EvidenceSet, RejectsReceiptsThatDisagreeOnCompatibility) {
    auto set = assemble("incompatible");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::DescriptorMismatch);
    EXPECT_NE(set.error().detail.find("workloadFingerprint"), std::string::npos);
}

// The descriptor must identify exactly the bytes it names before any of their
// meaning is read.
TEST(EvidenceSet, RejectsADescriptorThatDisagreesWithItsBytes) {
    auto set = assemble("corrupt-descriptor");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::DescriptorMismatch);
}

// A failed workload is evidence, not an error in the ledger. It is recorded
// with its terminal status and left out of the eligible set.
TEST(EvidenceSet, RecordsAWorkloadFailureWithoutMakingItEligible) {
    auto set = assemble("workload-failure");
    ASSERT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d16"), "workload_failure");
    EXPECT_EQ(eligibleIdentities(*set).size(), 4U);
}

// An attempt that produced nothing is still an attempt. Recording it as a
// status rather than an absence is what keeps a missing run distinguishable
// from a question nobody asked.
TEST(EvidenceSet, RecordsAnAttemptThatProducedNoReceipt) {
    auto set = assemble("no-receipt");
    ASSERT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d13"), kNoReceiptStatus);
    EXPECT_EQ(eligibleIdentities(*set).size(), 4U);
}

// Every terminal status SPEC-0014 defines is carried into the ledger, one case
// per value, so none of them can quietly stop being represented. Only the
// completed one is eligible; none of the other four is discardable.
TEST(EvidenceSet, CarriesEveryTerminalStatusAndDiscardsNone) {
    auto set = assemble("every-status");
    ASSERT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d11"), "completed");
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d16"), "workload_failure");
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d17"), "invalid_environment");
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d30"), "invalid_harness");
    EXPECT_EQ(statusOf(*set, "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d31"), "infrastructure_error");
    EXPECT_EQ(set->find("attempts")->elements().size(), 5U);
    EXPECT_EQ(eligibleIdentities(*set).size(), 1U);
}

// An attempt that names a repetition the schedule does not contain is refused.
// The plan is the only statement of what was scheduled, so an entry outside it
// cannot be admitted by being present.
TEST(EvidenceSet, RejectsAnAttemptOutsideTheDeclaredSchedule) {
    auto set = assemble("unplanned-repetition");
    ASSERT_FALSE(set.has_value());
    EXPECT_EQ(set.error().rejection, RecordRejection::SchemaInvalid);
}

// A retry supersedes the attempt it replaces. Both remain in the ledger; only
// the replacement is eligible.
TEST(EvidenceSet, KeepsASupersededAttemptInTheLedgerAndOutOfTheEligibleSet) {
    auto set = assemble("retry-chain");
    ASSERT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    constexpr std::string_view kSuperseded = "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d17";
    EXPECT_EQ(statusOf(*set, kSuperseded), "invalid_environment");
    const auto kEligible = eligibleIdentities(*set);
    EXPECT_EQ(kEligible.size(), 5U);
    EXPECT_EQ(std::ranges::find(kEligible, kSuperseded), kEligible.end());
}

// The committed bytes are the golden vector. Assembling the same plan against
// the same receipts must reproduce them exactly on every host: a difference
// here is a determinism defect, not a host difference, because nothing in the
// inputs varies by platform.
TEST(EvidenceSet, ReproducesTheCommittedCanonicalBytesExactly) {
    auto set = assemble("complete");
    ASSERT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    const std::string kCommitted = readAllBytes(fixtureRoot() / "canonical/evidence-set-v1.canonical.json");
    EXPECT_EQ(serializeCanonical(*set), kCommitted);
}

// Assembly orders by the plan's declared ordinals, not by the order the plan
// happened to list its attempts in. Two plans differing only in listing order
// must produce identical bytes, or the identity of a set would depend on how it
// was written down.
TEST(EvidenceSet, AssemblesIdenticalBytesRegardlessOfTheOrderAttemptsAreListed) {
    auto plan = parsePlan("complete");
    ASSERT_TRUE(plan.has_value()) << (plan ? std::string{} : plan.error().detail);
    auto reversed = *plan;
    std::ranges::reverse(reversed.attempts);

    const auto kStore = populatedStore();
    auto first = assembleEvidenceSet(kStore, *plan, kSetId);
    auto second = assembleEvidenceSet(kStore, reversed, kSetId);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(serializeCanonical(*first), serializeCanonical(*second));
}

} // namespace rawframe::tool::evidence
