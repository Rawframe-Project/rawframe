#include "blob_store.h"
#include "canonical_json.h"
#include "evaluation_policy.h"
#include "evaluator.h"
#include "evidence_set.h"
#include "metric_registry.h"
#include "record_gate.h"

#include <array>
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

std::string readAllBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing fixture: " << path.generic_string();
    std::ostringstream content;
    content << input.rdbuf();
    return content.str();
}

// A directory of this case's own, named from the case rather than from a
// counter. Each case is a separate CTest test running in its own process, so a
// counter would hand every case the same path and let them delete each other's
// working files under parallel execution.
std::filesystem::path caseRoot() {
    const auto* kInfo = ::testing::UnitTest::GetInstance()->current_test_info();
    const std::string kName =
        kInfo == nullptr ? std::string{"unknown"} : std::string(kInfo->test_suite_name()) + "." + kInfo->name();
    std::uint32_t leaf = 2166136261U;
    for (const char kCharacter : kName) {
        leaf = (leaf ^ static_cast<unsigned char>(kCharacter)) * 16777619U;
    }
    constexpr std::array<char, 16> kDigits{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string label(8, '0');
    for (std::size_t index = 0; index < 8; ++index) {
        label.at(7 - index) = kDigits.at((leaf >> (index * 4)) & 0xFU);
    }
    const std::filesystem::path kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "ev" / label;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    return kRoot;
}

BlobStore populatedStore(const std::filesystem::path& root) {
    const std::filesystem::path kBlobs = root / "blobs" / "sha256";
    std::filesystem::create_directories(kBlobs);
    BlobStore store(kBlobs);
    for (const auto& kEntry : std::filesystem::directory_iterator(fixtureRoot() / "receipts")) {
        const auto kStored = store.put(kEntry.path());
        EXPECT_TRUE(kStored.has_value()) << kEntry.path().generic_string();
    }
    return store;
}

// The maintained registry and policy, read from `evidence/` rather than from a
// fixture. An evaluator tested against a copy of its authorities would keep
// passing after the real ones changed, which is the one thing these tests exist
// to notice.
MetricRegistry maintainedRegistry() {
    const auto kPath = repositoryRoot() / "evidence/registries/metric-registry-v1.json";
    auto record = ingestCanonicalBytes(readAllBytes(kPath));
    EXPECT_TRUE(record.has_value());
    auto registry = parseMetricRegistry(repositoryRoot(), kPath, *record);
    EXPECT_TRUE(registry.has_value()) << (registry ? std::string{} : registry.error().detail);
    return registry ? *registry : MetricRegistry{};
}

EvaluationPolicy maintainedPolicy() {
    const auto kPath = repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json";
    auto record = ingestCanonicalBytes(readAllBytes(kPath));
    EXPECT_TRUE(record.has_value());
    auto policy = parseEvaluationPolicy(repositoryRoot(), kPath, *record);
    EXPECT_TRUE(policy.has_value()) << (policy ? std::string{} : policy.error().detail);
    return policy ? *policy : EvaluationPolicy{};
}

Descriptor describeFile(const std::filesystem::path& path, std::string_view mediaType) {
    auto descriptor = describeBytes(readAllBytes(path), mediaType);
    EXPECT_TRUE(descriptor.has_value());
    return descriptor ? *descriptor : Descriptor{};
}

constexpr std::string_view kEvaluationId = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
constexpr std::string_view kSetId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

EvaluationInputs inputsFor(const std::filesystem::path& setPath) {
    return EvaluationInputs{
        .repositoryRoot = repositoryRoot(),
        .evidenceSetPath = setPath,
        .evidenceSetDescriptor = describeFile(setPath, kEvidenceSetMediaType),
        .metricRegistryDescriptor =
            describeFile(repositoryRoot() / "evidence/registries/metric-registry-v1.json", kMetricRegistryMediaType),
        .evaluationPolicyDescriptor = describeFile(
            repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json", kEvaluationPolicyMediaType)};
}

// Assembles the named plan into an Evidence Set, writes it where the schema
// oracle can read it, and evaluates it. Building the set through assembly
// rather than writing one by hand is what keeps these cases honest: the
// evaluator is handed exactly what the ledger authority produces.
RecordResult<CanonicalValue> evaluatePlan(std::string_view planName) {
    const auto kRoot = caseRoot();
    const auto kPlanPath = fixtureRoot() / "plans" / (std::string(planName) + ".json");
    auto planRecord = ingestCanonicalBytes(readAllBytes(kPlanPath));
    EXPECT_TRUE(planRecord.has_value()) << planName;
    if (!planRecord) {
        return std::unexpected(RecordFailure{RecordRejection::MalformedInput, "fixture did not parse"});
    }
    auto plan = parseAttemptPlan(repositoryRoot(), kPlanPath, *planRecord);
    EXPECT_TRUE(plan.has_value()) << (plan ? std::string{} : plan.error().detail);
    if (!plan) {
        return std::unexpected(plan.error());
    }

    const BlobStore kStore = populatedStore(kRoot);
    auto set = assembleEvidenceSet(kStore, *plan, kSetId);
    EXPECT_TRUE(set.has_value()) << (set ? std::string{} : set.error().detail);
    if (!set) {
        return std::unexpected(set.error());
    }

    const std::filesystem::path kSetPath = kRoot / "evidence-set.json";
    std::ofstream(kSetPath, std::ios::binary) << serializeCanonical(*set);
    return evaluateEvidenceSet(
        kStore, inputsFor(kSetPath), *set, maintainedRegistry(), maintainedPolicy(), kEvaluationId);
}

// Evaluates one of the hand-written Evidence Sets. They cover the contradictions
// assembly cannot produce, so each one is the accepted shape with exactly one
// thing wrong.
RecordResult<CanonicalValue> evaluateSet(std::string_view setName) {
    const auto kRoot = caseRoot();
    const auto kSource = fixtureRoot() / "sets" / (std::string(setName) + ".json");
    const std::filesystem::path kSetPath = kRoot / "evidence-set.json";
    std::filesystem::copy_file(kSource, kSetPath);
    auto set = ingestCanonicalBytes(readAllBytes(kSetPath));
    EXPECT_TRUE(set.has_value()) << setName;
    if (!set) {
        return std::unexpected(set.error());
    }
    const BlobStore kStore = populatedStore(kRoot);
    return evaluateEvidenceSet(
        kStore, inputsFor(kSetPath), *set, maintainedRegistry(), maintainedPolicy(), kEvaluationId);
}

std::string verdictOf(const CanonicalValue& receipt) {
    const auto* kVerdict = receipt.find("verdict");
    EXPECT_NE(kVerdict, nullptr);
    if (kVerdict == nullptr) {
        return {};
    }
    const auto* kOutcome = kVerdict->find("outcome");
    return kOutcome == nullptr ? std::string{} : kOutcome->text();
}

std::string blockingPhaseOf(const CanonicalValue& receipt) {
    const auto* kVerdict = receipt.find("verdict");
    if (kVerdict == nullptr) {
        return {};
    }
    const auto* kPhase = kVerdict->find("blockingPhase");
    return kPhase == nullptr ? std::string{} : kPhase->text();
}

const CanonicalValue* checkFor(const CanonicalValue& receipt, std::string_view policyKey) {
    const auto* kChecks = receipt.find("checks");
    EXPECT_NE(kChecks, nullptr);
    if (kChecks == nullptr) {
        return nullptr;
    }
    for (const auto& kCheck : kChecks->elements()) {
        const auto* kKey = kCheck.find("policyKey");
        if (kKey != nullptr && kKey->text() == policyKey) {
            return &kCheck;
        }
    }
    return nullptr;
}

std::string memberText(const CanonicalValue* value, std::string_view member) {
    if (value == nullptr) {
        return {};
    }
    const auto* kMember = value->find(member);
    return kMember == nullptr ? std::string{} : kMember->text();
}

} // namespace

// The anchor. Every rejecting case below changes exactly one thing about
// evidence built the same way, so none of them can pass because evaluation
// stopped happening at all.
TEST(Evaluator, PassesEvidenceThatMeetsEveryBoundInThePolicy) {
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    EXPECT_EQ(verdictOf(*receipt), "passed");
    EXPECT_TRUE(blockingPhaseOf(*receipt).empty());
    const auto* kVerdict = receipt->find("verdict");
    ASSERT_NE(kVerdict, nullptr);
    EXPECT_EQ(kVerdict->find("checkCount")->integer(), 5);
    EXPECT_EQ(kVerdict->find("failedCheckCount")->integer(), 0);
    EXPECT_EQ(kVerdict->find("notRunCheckCount")->integer(), 0);
}

// The receipt has to satisfy its own schema. An emitter that produced a record
// its schema would refuse would make the schema decorative, and the oracle is
// the only thing that can say so independently of the code that wrote it.
TEST(Evaluator, EmitsAReceiptTheSchemaOracleAccepts) {
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    const std::filesystem::path kPath = caseRoot() / "evaluation-receipt.json";
    std::ofstream(kPath, std::ios::binary) << serializeCanonical(*receipt);
    const auto kValid = validateAgainstSchema(repositoryRoot(), kEvaluationReceiptSchemaPath, kPath);
    EXPECT_TRUE(kValid.has_value()) << (kValid ? std::string{} : kValid.error().detail);
}

// Tier 0 is diagnostic and untrusted, and a pass here claims nothing about
// performance, the runner, provenance, promotion, or any comparison. The record
// says so in its own bytes because a verdict is exactly the artifact that later
// gets quoted without its context.
TEST(Evaluator, DeniesEveryClaimAPassCouldBeMistakenFor) {
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value());
    EXPECT_EQ(receipt->find("tier")->text(), "tier_0");
    EXPECT_EQ(receipt->find("trust")->find("provenance")->text(), "diagnostic_untrusted");
    const auto* kScope = receipt->find("claimScope");
    ASSERT_NE(kScope, nullptr);
    for (const std::string_view kClaim :
         {"performanceClaim", "runnerClaim", "trustedProvenanceClaim", "promotionClaim", "relativeComparisonClaim"}) {
        const auto* kMember = kScope->find(kClaim);
        ASSERT_NE(kMember, nullptr) << kClaim;
        EXPECT_FALSE(kMember->boolean()) << kClaim;
    }
}

// Every input is named by descriptor rather than by path, and every eligible
// receipt is listed. A receipt that was read but not accounted for would be
// evidence nobody could check afterwards.
TEST(Evaluator, BindsEveryInputByDescriptorIncludingEachReceiptItRead) {
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value());
    const auto* kInputs = receipt->find("inputs");
    ASSERT_NE(kInputs, nullptr);
    EXPECT_EQ(memberText(kInputs->find("metricRegistry"), "mediaType"), kMetricRegistryMediaType);
    EXPECT_EQ(memberText(kInputs->find("evaluationPolicy"), "mediaType"), kEvaluationPolicyMediaType);
    EXPECT_EQ(memberText(kInputs->find("evidenceSet"), "mediaType"), kEvidenceSetMediaType);
    const auto* kReceipts = kInputs->find("receipts");
    ASSERT_NE(kReceipts, nullptr);
    EXPECT_EQ(kReceipts->elements().size(), 2U);
}

// A hard ceiling at zero, breached by exactly one. The breach is the evidence's
// verdict and not a failure to evaluate: a receipt exists and says failed.
TEST(Evaluator, FailsAHardCeilingBreachAndSaysWhichCheckBrokeIt) {
    auto receipt = evaluatePlan("evaluable-breach");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    EXPECT_EQ(verdictOf(*receipt), "failed");
    EXPECT_EQ(blockingPhaseOf(*receipt), "hard_ceiling");
    const auto* kCheck = checkFor(*receipt, "assertions_held");
    ASSERT_NE(kCheck, nullptr);
    EXPECT_EQ(memberText(kCheck, "outcome"), "failed");
    EXPECT_EQ(memberText(kCheck, "reason"), "bound_violated");
}

// One run breached and one did not. Every eligible run has to meet the bound,
// so a passing sibling cannot average a breach away.
TEST(Evaluator, FailsWhenOnlyOneEligibleRunBreachesTheBound) {
    auto receipt = evaluatePlan("evaluable-breach");
    ASSERT_TRUE(receipt.has_value());
    const auto* kCheck = checkFor(*receipt, "assertions_held");
    ASSERT_NE(kCheck, nullptr);
    const auto* kObservations = kCheck->find("observations");
    ASSERT_NE(kObservations, nullptr);
    EXPECT_EQ(kObservations->elements().size(), 2U);
}

// One run reported the metric and the other did not. The check fails on the
// silence rather than deciding from the run that spoke: a quiet run is
// indistinguishable from a run whose result nobody wanted recorded, and letting
// a reporting sibling cover it is exactly how a gap becomes an accidental pass.
TEST(Evaluator, FailsACheckOneEligibleRunDidNotObserve) {
    auto receipt = evaluatePlan("evaluable-gap");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    EXPECT_EQ(verdictOf(*receipt), "failed");
    EXPECT_EQ(blockingPhaseOf(*receipt), "completeness");
    const auto* kCheck = checkFor(*receipt, "attachments_retrievable");
    ASSERT_NE(kCheck, nullptr);
    EXPECT_EQ(memberText(kCheck, "outcome"), "failed");
    EXPECT_EQ(memberText(kCheck, "reason"), "observation_missing");
}

// The first failing phase stops the later ones, and their checks are retained
// saying so. Dropping them would make a check nobody reached look the same as a
// check that was never written.
TEST(Evaluator, RetainsLaterPhaseChecksAsNotRunRatherThanOmittingThem) {
    auto receipt = evaluatePlan("evaluable-gap");
    ASSERT_TRUE(receipt.has_value());
    const auto* kVerdict = receipt->find("verdict");
    ASSERT_NE(kVerdict, nullptr);
    EXPECT_EQ(kVerdict->find("checkCount")->integer(), 5);
    EXPECT_GT(kVerdict->find("notRunCheckCount")->integer(), 0);
    const auto* kLater = checkFor(*receipt, "assertions_held");
    ASSERT_NE(kLater, nullptr);
    EXPECT_EQ(memberText(kLater, "outcome"), "not_run");
    EXPECT_EQ(memberText(kLater, "reason"), "earlier_phase_failed");
}

// Completeness before correctness before hard ceilings, as SPEC-0014 orders
// them. The emitted order is the phase order and not the order the policy
// happened to list its entries in.
TEST(Evaluator, EmitsChecksInPhaseOrderAndThenByKey) {
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value());
    const auto* kChecks = receipt->find("checks");
    ASSERT_NE(kChecks, nullptr);
    std::vector<std::string> observed;
    observed.reserve(kChecks->elements().size());
    for (const auto& kCheck : kChecks->elements()) {
        observed.push_back(memberText(&kCheck, "phase") + ":" + memberText(&kCheck, "policyKey"));
    }
    // The whole sequence at once. Comparing positions one at a time would let a
    // reordering pass whichever positions nobody happened to name.
    const std::vector<std::string> kExpected{"completeness:attachments_retrievable",
                                             "completeness:observations_present",
                                             "hard_ceiling:assertions_held",
                                             "hard_ceiling:invariants_held",
                                             "hard_ceiling:workload_completed"};
    EXPECT_EQ(observed, kExpected);
}

// ADR-0019 makes an observation the registry does not declare diagnostic rather
// than gating. It is neither an error nor a check: it simply cannot decide
// anything, so the evaluation is identical with and without it.
//
// TASK-0006 verification item 5 asked for the opposite, and the accepted
// decision outranks the Task packet under the repository's authority order.
TEST(Evaluator, TreatsAnUndeclaredObservationAsDiagnosticRatherThanGating) {
    auto receipt = evaluatePlan("evaluable-diagnostic");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    EXPECT_EQ(verdictOf(*receipt), "passed");
    const auto* kChecks = receipt->find("checks");
    ASSERT_NE(kChecks, nullptr);
    for (const auto& kCheck : kChecks->elements()) {
        EXPECT_NE(memberText(&kCheck, "metricId"), "tick.duration");
    }
}

// A declared metric reported in another unit is not the same quantity, and no
// comparison between the two would mean anything. This fails the evaluation
// rather than one check, because nothing here can be salvaged into a verdict.
TEST(Evaluator, RefusesADeclaredMetricReportedInAnotherUnit) {
    auto receipt = evaluatePlan("evaluable-unit");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

TEST(Evaluator, RefusesADeclaredMetricReportedAsAnotherStatistic) {
    auto receipt = evaluatePlan("evaluable-statistic");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

// Two observations of one declared metric contradict each other. Choosing
// between them is exactly the judgement an evaluator must not make.
TEST(Evaluator, RefusesAReceiptThatReportsOneMetricTwice) {
    auto receipt = evaluatePlan("evaluable-duplicate");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::SchemaInvalid);
}

// The same quantity at a finer scale compares exactly. The bound moves to where
// the observation is, which is the direction that keeps a breach visible.
TEST(Evaluator, ComparesAnObservationStatedAtAFinerScaleWithoutRounding) {
    auto receipt = evaluatePlan("evaluable-scaled");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    EXPECT_EQ(verdictOf(*receipt), "passed");
    const auto* kCheck = checkFor(*receipt, "observations_present");
    ASSERT_NE(kCheck, nullptr);
    const auto* kObservations = kCheck->find("observations");
    ASSERT_NE(kObservations, nullptr);
    ASSERT_EQ(kObservations->elements().size(), 1U);
    EXPECT_EQ(kObservations->elements().front().find("scaleExponent")->integer(), -3);
    // The bound is recorded as the policy wrote it, unmoved. A rescaled bound in
    // the record would state a threshold the authority never set.
    EXPECT_EQ(kCheck->find("bound")->find("value")->integer(), 1);
    EXPECT_EQ(kCheck->find("bound")->find("scaleExponent")->integer(), 0);
}

// A coarser scale than the bound can be represented in. The accepted rounding is
// reject_inexact, so the evaluation fails rather than rounding a threshold away.
TEST(Evaluator, RefusesAComparisonThatWouldRoundTheBound) {
    auto receipt = evaluatePlan("evaluable-inexact");
    ASSERT_FALSE(receipt.has_value());
}

// Evidence produced against another registry generation is not comparable
// against this one. Normalizing it would be the evaluator deciding two
// generations meant the same thing.
TEST(Evaluator, RefusesEvidenceProducedAgainstAnotherRegistryGeneration) {
    auto receipt = evaluatePlan("evaluable-registry-2");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

TEST(Evaluator, RefusesASetWhoseCompatibilityNamesAnotherRegistryGeneration) {
    auto receipt = evaluateSet("registry-generation-mismatch");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

// Tier 0 is the only tier this gate can reach. A higher tier requires compatible
// evidence from a qualified cell, which does not exist, so claiming one here is
// refused rather than evaluated at Tier 0 and reported as the higher tier.
TEST(Evaluator, RefusesASetClaimingATierThisGateCannotReach) {
    auto receipt = evaluateSet("higher-tier");
    ASSERT_FALSE(receipt.has_value());
}

// Zero eligible runs is not a vacuous pass. Nothing was observed, so every check
// fails for the reason that nothing was observed.
TEST(Evaluator, FailsEveryCheckWhenNoAttemptIsEligible) {
    auto receipt = evaluateSet("no-eligible-attempt");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    EXPECT_EQ(verdictOf(*receipt), "failed");
    EXPECT_EQ(blockingPhaseOf(*receipt), "completeness");
    EXPECT_EQ(memberText(checkFor(*receipt, "observations_present"), "reason"), "observation_missing");
}

TEST(Evaluator, RefusesASetNamingAnEligibleIdentityItNeverDeclares) {
    auto receipt = evaluateSet("eligible-attempt-unknown");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(Evaluator, RefusesAnEligibleAttemptThatCarriesNoReceipt) {
    auto receipt = evaluateSet("eligible-attempt-without-receipt");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::SchemaInvalid);
}

// A receipt the set names but the store does not hold. The evaluation stops
// rather than proceeding on the runs it could find, because a verdict reached
// from a subset of the declared evidence is a verdict about a different set.
TEST(Evaluator, RefusesEvidenceWhoseReceiptTheStoreDoesNotHold) {
    auto receipt = evaluateSet("receipt-absent-from-store");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

// The descriptor must identify exactly the bytes it names, checked before any of
// their meaning is read.
TEST(Evaluator, RefusesAReceiptDescriptorThatDisagreesWithItsBytes) {
    auto receipt = evaluateSet("receipt-descriptor-length");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

TEST(Evaluator, RefusesAReceiptDescriptorClaimingAnotherMediaType) {
    auto receipt = evaluateSet("receipt-foreign-media-type");
    ASSERT_FALSE(receipt.has_value());
    EXPECT_EQ(receipt.error().rejection, RecordRejection::DescriptorMismatch);
}

// An evaluation is a function of its inputs and of nothing else. The same
// inputs must produce the same bytes, or the receipt would be evidence about
// when it ran rather than about what it read.
TEST(Evaluator, ProducesIdenticalBytesFromIdenticalInputs) {
    auto first = evaluatePlan("evaluable-pass");
    auto second = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(serializeCanonical(*first), serializeCanonical(*second));
}

// The committed bytes are the golden vector. Evaluating the same evidence
// against the same authorities must reproduce them exactly on every host: a
// difference here is a determinism defect rather than a host difference,
// because nothing in the inputs varies by platform.
TEST(Evaluator, ReproducesTheCommittedCanonicalBytesExactly) {
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value()) << (receipt ? std::string{} : receipt.error().detail);
    const std::string kCommitted = readAllBytes(fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json");
    EXPECT_EQ(serializeCanonical(*receipt), kCommitted);
}

// Evaluation reads. Every input has to be byte-identical afterwards, because an
// evaluator that repaired, normalized, or rewrote what it judged would be
// deciding about bytes that no longer exist.
TEST(Evaluator, LeavesEveryInputByteIdenticalAfterEvaluating) {
    const std::array kInputs{repositoryRoot() / "evidence/registries/metric-registry-v1.json",
                             repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json",
                             fixtureRoot() / "receipts/evaluable-1.json",
                             fixtureRoot() / "receipts/evaluable-2.json"};
    std::vector<std::string> before;
    before.reserve(kInputs.size());
    for (const auto& kPath : kInputs) {
        before.push_back(readAllBytes(kPath));
    }
    auto receipt = evaluatePlan("evaluable-pass");
    ASSERT_TRUE(receipt.has_value());
    for (std::size_t index = 0; index < kInputs.size(); ++index) {
        EXPECT_EQ(readAllBytes(kInputs.at(index)), before.at(index)) << kInputs.at(index).generic_string();
    }
}

} // namespace rawframe::tool::evidence
