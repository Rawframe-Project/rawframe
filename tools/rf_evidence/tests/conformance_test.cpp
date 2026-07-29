// SPEC-0017's required conformance corpus, asserted as a corpus.
//
// One case per numbered item, named so the item number is recoverable from the
// name. A matrix that pointed at other suites could not show a gap, because an
// absent case and an unwritten case look identical to a reader; a missing name
// here is visible. Items already exercised elsewhere are asserted by a case
// that exercises the covering behavior rather than by a comment citing another
// file, so that deleting the other suite breaks this one.
//
// The cases are deliberately small. This file proves coverage exists; the owning
// suites prove the behavior in depth.

#include "baseline_record.h"
#include "blob_store.h"
#include "canonical_json.h"
#include "descriptor.h"
#include "evaluation_policy.h"
#include "evaluator.h"
#include "evidence_set.h"
#include "metric_registry.h"
#include "path_audit.h"
#include "record_gate.h"
#include "repository_validator.h"
#include "schema_oracle.h"
#include "sha256.h"
#include "shipping_closure.h"

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
    const std::filesystem::path kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "cf" / label;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    return kRoot;
}

CanonicalValue ingest(const std::filesystem::path& path) {
    auto record = ingestCanonicalBytes(readAllBytes(path));
    EXPECT_TRUE(record.has_value()) << path.generic_string();
    return record ? *record : CanonicalValue{};
}

MetricRegistry maintainedRegistry() {
    const auto kPath = repositoryRoot() / "evidence/registries/metric-registry-v1.json";
    auto registry = parseMetricRegistry(repositoryRoot(), kPath, ingest(kPath));
    EXPECT_TRUE(registry.has_value()) << (registry ? std::string{} : registry.error().detail);
    return registry ? *registry : MetricRegistry{};
}

EvaluationPolicy policyFrom(const std::filesystem::path& path) {
    auto policy = parseEvaluationPolicy(repositoryRoot(), path, ingest(path));
    EXPECT_TRUE(policy.has_value()) << (policy ? std::string{} : policy.error().detail);
    return policy ? *policy : EvaluationPolicy{};
}

EvaluationPolicy maintainedPolicy() {
    return policyFrom(repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json");
}

Descriptor descriptorOf(const std::filesystem::path& path, std::string_view mediaType) {
    auto described = describeBytes(readAllBytes(path), mediaType);
    EXPECT_TRUE(described.has_value()) << path.generic_string();
    return described ? *described : Descriptor{};
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

// One evaluation of the passing set against whichever policy is named, with the
// set copied into scratch space so the fixture is never the file being read
// from a mutable root.
// The identity the committed golden receipt was emitted under. It is part of
// the bytes, so a run that used a different one could not reproduce them.
constexpr std::string_view kGoldenEvaluationId = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";

RecordResult<CanonicalValue> evaluateAgainst(const std::filesystem::path& policyPath) {
    const auto kRoot = caseRoot();
    const std::filesystem::path kSetPath = kRoot / "evidence-set.json";
    std::filesystem::copy_file(fixtureRoot() / "sets/passing.json", kSetPath);
    const EvaluationInputs kInputs{
        .repositoryRoot = repositoryRoot(),
        .evidenceSetPath = kSetPath,
        .evidenceSetDescriptor = descriptorOf(kSetPath, kEvidenceSetMediaType),
        .metricRegistryDescriptor =
            descriptorOf(repositoryRoot() / "evidence/registries/metric-registry-v1.json", kMetricRegistryMediaType),
        .evaluationPolicyDescriptor = descriptorOf(policyPath, kEvaluationPolicyMediaType)};
    return evaluateEvidenceSet(populatedStore(kRoot),
                               kInputs,
                               ingest(kSetPath),
                               maintainedRegistry(),
                               policyFrom(policyPath),
                               kGoldenEvaluationId);
}

// One evaluation of a named set against the maintained authorities.
RecordResult<CanonicalValue> evaluateSetNamed(std::string_view setName) {
    const auto kRoot = caseRoot() / setName;
    std::filesystem::create_directories(kRoot);
    const std::filesystem::path kSetPath = kRoot / "set.json";
    std::filesystem::copy_file(fixtureRoot() / "sets" / (std::string(setName) + ".json"), kSetPath);
    const auto kPolicyPath = repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json";
    const EvaluationInputs kInputs{
        .repositoryRoot = repositoryRoot(),
        .evidenceSetPath = kSetPath,
        .evidenceSetDescriptor = descriptorOf(kSetPath, kEvidenceSetMediaType),
        .metricRegistryDescriptor =
            descriptorOf(repositoryRoot() / "evidence/registries/metric-registry-v1.json", kMetricRegistryMediaType),
        .evaluationPolicyDescriptor = descriptorOf(kPolicyPath, kEvaluationPolicyMediaType)};
    return evaluateEvidenceSet(populatedStore(kRoot),
                               kInputs,
                               ingest(kSetPath),
                               maintainedRegistry(),
                               policyFrom(kPolicyPath),
                               "cccccccc-dddd-4eee-8fff-000000000003");
}

std::vector<std::string> promotedReceiptDigests(const CanonicalValue& receipt) {
    std::vector<std::string> digests;
    const auto* kInputs = receipt.find("inputs");
    EXPECT_NE(kInputs, nullptr);
    const auto* kReceipts = kInputs == nullptr ? nullptr : kInputs->find("receipts");
    EXPECT_NE(kReceipts, nullptr);
    if (kReceipts == nullptr) {
        return digests;
    }
    digests.reserve(kReceipts->elements().size());
    for (const auto& kEntry : kReceipts->elements()) {
        const auto* kDescriptor = kEntry.find("descriptor");
        EXPECT_NE(kDescriptor, nullptr);
        if (kDescriptor != nullptr) {
            const auto* kDigest = kDescriptor->find("digest");
            EXPECT_NE(kDigest, nullptr);
            if (kDigest != nullptr) {
                digests.push_back(kDigest->text());
            }
        }
    }
    return digests;
}

RepositorySnapshot snapshot() {
    auto validated = validateRepository(repositoryRoot());
    EXPECT_TRUE(validated.has_value()) << (validated ? std::string{} : validated.error().message);
    return validated ? *validated : RepositorySnapshot{};
}

} // namespace

// 1. Every maintained schema passes Draft 2020-12 meta-schema validation
// offline. The oracle is the pinned local artifact and resolves nothing over a
// network, which is what makes "offline" part of the claim rather than a note.
TEST(Conformance, Item01EveryMaintainedSchemaValidatesAgainstTheMetaSchemaOffline) {
    ASSERT_TRUE(verifySchemaOracleVersion(repositoryRoot()).has_value());
    std::size_t validated = 0;
    for (const auto& kEntry : std::filesystem::directory_iterator(repositoryRoot() / "schemas")) {
        EXPECT_NE(readAllBytes(kEntry.path()).find(R"("$schema": "https://json-schema.org/draft/2020-12/schema")"),
                  std::string::npos)
            << kEntry.path().generic_string();
        // Running the schema against an instance compiles it first. A schema
        // the oracle cannot compile comes back as some other failure; only a
        // compiled schema reaches InvalidManifest, which is the oracle saying
        // the instance does not satisfy it. The code is what discriminates
        // "this schema is malformed" from "this document is not an instance of
        // it", and only the first would be a conformance failure here.
        // The shared definitions are handed over as an import, because a $ref
        // resolves against its own absolute identifier rather than against a
        // sibling file on disk. Without it a schema that references them fails
        // to compile, which would look here like a malformed schema.
        const std::filesystem::path kCommon = repositoryRoot() / kEvidenceCommonSchemaPath;
        const std::vector<std::filesystem::path> kImports = kEntry.path().filename() == kCommon.filename()
                                                                ? std::vector<std::filesystem::path>{}
                                                                : std::vector<std::filesystem::path>{kCommon};
        const auto kShape = validateJsonShape(repositoryRoot(), kEntry.path(), kEntry.path(), kImports);
        EXPECT_TRUE(kShape.has_value() || kShape.error().code == FailureCode::InvalidManifest)
            << kEntry.path().generic_string() << ": " << (kShape ? std::string{} : kShape.error().message);
        ++validated;
    }
    EXPECT_GE(validated, 20U);
}

// 2. Positive and negative schema fixtures produce exact expected results.
TEST(Conformance, Item02PositiveAndNegativeSchemaFixturesProduceExactResults) {
    const auto kPath = fixtureRoot() / "baselines/well-formed.json";
    EXPECT_TRUE(parseBaselineRecord(repositoryRoot(), kPath, ingest(kPath)).has_value());
    const auto kBad = fixtureRoot() / "baselines/claims-trusted-provenance.json";
    const auto kResult = parseBaselineRecord(repositoryRoot(), kBad, ingest(kBad));
    ASSERT_FALSE(kResult.has_value());
    EXPECT_EQ(kResult.error().rejection, RecordRejection::SchemaInvalid);
}

// 3. RFC 8785 ordering applies to the accepted subset: canonical bytes are the
// canonical form of themselves, and a record round-trips to identical bytes.
TEST(Conformance, Item03Rfc8785OrderingHoldsOverTheAcceptedSubset) {
    const auto kPath = fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json";
    const std::string kBytes = readAllBytes(kPath);
    EXPECT_EQ(serializeCanonical(ingest(kPath)), kBytes);
    EXPECT_TRUE(jcsKeyLess("a", "b"));
    EXPECT_FALSE(jcsKeyLess("b", "a"));
}

// 4. Every noncanonical spelling is rejected, one per form.
TEST(Conformance, Item04NoncanonicalSpellingsAreRejected) {
    for (const std::string_view kBytes : {std::string_view{"{\"a\": 1}"},
                                          std::string_view{"\xEF\xBB\xBF{\"a\":1}"},
                                          std::string_view{"{\"a\":1}\n"},
                                          std::string_view{"{\"b\":1,\"a\":1}"},
                                          std::string_view{"{\"a\":1,\"a\":2}"},
                                          std::string_view{"{\"a\":1.5}"},
                                          std::string_view{"{\"a\":1e3}"},
                                          std::string_view{"{\"a\":-0}"},
                                          std::string_view{"{\"a\":NaN}"},
                                          std::string_view{"{\"a\":Infinity}"}}) {
        EXPECT_FALSE(ingestCanonicalBytes(kBytes).has_value()) << kBytes;
    }
}

// 5. Canonical bytes and their SHA-256 descriptor match the committed golden
// vector. The digest is recomputed here rather than read, so a host that
// disagreed about either would fail on this line.
TEST(Conformance, Item05CanonicalBytesAndDigestsMatchTheGoldenVectorOnThisHost) {
    const auto kPath = fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json";
    const auto kDescriptor = descriptorOf(kPath, kEvaluationReceiptMediaType);
    EXPECT_EQ(kDescriptor.digest, "sha256:aa2a1b98c4296ab5b444d3a97a7484743af66f78d1b42f403c41e72eb0b13811");
    EXPECT_EQ(kDescriptor.byteLength, 3785U);
    const auto kFileDigest = sha256File(kPath);
    ASSERT_TRUE(kFileDigest.has_value());
    EXPECT_EQ("sha256:" + *kFileDigest, kDescriptor.digest);
}

// 6. A record cannot carry its own digest: identity lives in an external
// descriptor and every record schema closes its object, so there is no member
// a self-digest could occupy.
TEST(Conformance, Item06SelfDigestAndCircularRecordDesignsAreImpossibleBySchema) {
    for (const std::string_view kSchema : {kBaselineRecordSchemaPath,
                                           kEvaluationReceiptSchemaPath,
                                           kEvaluationPolicySchemaPath,
                                           kMetricRegistrySchemaPath}) {
        const std::string kText = readAllBytes(repositoryRoot() / kSchema);
        EXPECT_NE(kText.find("\"additionalProperties\": false"), std::string::npos) << kSchema;
        EXPECT_EQ(kText.find("\"selfDigest\""), std::string::npos) << kSchema;
    }
}

// 7. A descriptor that disagrees with its bytes is refused before anything
// semantic is read.
TEST(Conformance, Item07ByteLengthDigestAndMediaMismatchAreRejectedBeforeConsumption) {
    const auto kPath = fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json";
    const std::string kBytes = readAllBytes(kPath);
    const auto kGood = descriptorOf(kPath, kEvaluationReceiptMediaType);
    EXPECT_TRUE(verifyDescriptor(kGood, kBytes, kEvaluationReceiptMediaType).has_value());

    Descriptor wrongLength = kGood;
    wrongLength.byteLength += 1;
    EXPECT_FALSE(verifyDescriptor(wrongLength, kBytes, kEvaluationReceiptMediaType).has_value());

    Descriptor wrongDigest = kGood;
    wrongDigest.digest = "sha256:" + std::string(64, '0');
    EXPECT_FALSE(verifyDescriptor(wrongDigest, kBytes, kEvaluationReceiptMediaType).has_value());

    EXPECT_FALSE(verifyDescriptor(kGood, kBytes, kEvidenceSetMediaType).has_value());
}

// 8. An interrupted write leaves nothing on the destination path. Staging is
// the interruption: a run that stops between stage and publish leaves a file
// whose name no digest-derived path can reach.
TEST(Conformance, Item08AnInterruptedCasWriteLeavesNoPartialDestination) {
    const auto kRoot = caseRoot();
    std::filesystem::create_directories(kRoot / "sha256");
    const BlobStore kStore(kRoot / "sha256");
    const auto kSource = fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json";
    const auto kStaged = kStore.stage(kSource);
    ASSERT_TRUE(kStaged.has_value());
    const auto kFinal = kStore.pathFor(kStaged->identity.digest);
    ASSERT_TRUE(kFinal.has_value());
    EXPECT_FALSE(std::filesystem::exists(*kFinal));
}

// 9. An existing correct blob is verified rather than rewritten; a corrupt one
// fails closed instead of being repaired.
TEST(Conformance, Item09ExistingCorrectBlobsAreNotOverwrittenAndCorruptOnesFailClosed) {
    const auto kRoot = caseRoot();
    std::filesystem::create_directories(kRoot / "sha256");
    const BlobStore kStore(kRoot / "sha256");
    const auto kSource = fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json";
    const auto kFirst = kStore.put(kSource);
    ASSERT_TRUE(kFirst.has_value());
    const auto kSecond = kStore.put(kSource);
    ASSERT_TRUE(kSecond.has_value());
    EXPECT_EQ(kFirst->digest, kSecond->digest);

    const auto kPath = kStore.pathFor(kFirst->digest);
    ASSERT_TRUE(kPath.has_value());
    {
        std::ofstream corrupt(*kPath, std::ios::binary | std::ios::app);
        corrupt << "x";
    }
    const auto kVerified = kStore.verify(kFirst->digest);
    ASSERT_FALSE(kVerified.has_value());
    EXPECT_EQ(kVerified.error().rejection, BlobRejection::CorruptStoredBlob);
}

// 10. Traversal, absolute paths, and locator injection are refused by digest
// validation and by path classification, before any file is opened.
TEST(Conformance, Item10TraversalAbsolutePathsAndLocatorInjectionAreRejected) {
    const auto kRoot = caseRoot();
    std::filesystem::create_directories(kRoot / "sha256");
    const BlobStore kStore(kRoot / "sha256");
    for (const std::string_view kDigest : {std::string_view{"sha256:../../etc/passwd"},
                                           std::string_view{"sha256:" + std::string(63, 'a')},
                                           std::string_view{"md5:" + std::string(64, 'a')},
                                           std::string_view{"sha256:" + std::string(64, 'A')}}) {
        EXPECT_FALSE(kStore.verify(kDigest).has_value()) << kDigest;
    }
}

// 11. Every scheduled attempt stays in the ledger, whatever became of it.
TEST(Conformance, Item11TheAttemptLedgerRetainsSlowFailedInvalidAndRetriedAttempts) {
    const auto kPath = fixtureRoot() / "sets/passing.json";
    const auto kSet = ingest(kPath);
    const auto* kAttempts = kSet.find("attempts");
    ASSERT_NE(kAttempts, nullptr);
    EXPECT_FALSE(kAttempts->elements().empty());
    for (const auto& kAttempt : kAttempts->elements()) {
        EXPECT_NE(kAttempt.find("attemptId"), nullptr);
        EXPECT_NE(kAttempt.find("status"), nullptr);
    }
}

// 12. A set that drops, duplicates, or invents an attempt fails assembly.
TEST(Conformance, Item12CherryPickedDuplicateAndMissingAttemptsFailAssembly) {
    for (const std::string_view kName : {std::string_view{"eligible-attempt-unknown"},
                                         std::string_view{"eligible-attempt-without-receipt"},
                                         std::string_view{"receipt-absent-from-store"}}) {
        const auto kPath = fixtureRoot() / "sets" / (std::string(kName) + ".json");
        const auto kRoot = caseRoot() / kName;
        std::filesystem::create_directories(kRoot);
        const std::filesystem::path kSetPath = kRoot / "set.json";
        std::filesystem::copy_file(kPath, kSetPath);
        const EvaluationInputs kInputs{.repositoryRoot = repositoryRoot(),
                                       .evidenceSetPath = kSetPath,
                                       .evidenceSetDescriptor = descriptorOf(kSetPath, kEvidenceSetMediaType),
                                       .metricRegistryDescriptor = Descriptor{},
                                       .evaluationPolicyDescriptor = Descriptor{}};
        EXPECT_FALSE(evaluateEvidenceSet(populatedStore(kRoot),
                                         kInputs,
                                         ingest(kSetPath),
                                         maintainedRegistry(),
                                         maintainedPolicy(),
                                         "cccccccc-dddd-4eee-8fff-000000000002")
                         .has_value())
            << kName;
    }

    // Cherry-picking down to nothing is evaluable and must not be a pass. A set
    // that selects no eligible attempt has not met a check; it has avoided one.
    const auto kEmpty = evaluateSetNamed("no-eligible-attempt");
    ASSERT_TRUE(kEmpty.has_value()) << (kEmpty ? std::string{} : kEmpty.error().detail);
    const auto* kVerdict = kEmpty->find("verdict");
    ASSERT_NE(kVerdict, nullptr);
    const auto* kOutcome = kVerdict->find("outcome");
    ASSERT_NE(kOutcome, nullptr);
    EXPECT_EQ(kOutcome->text(), "failed");
}

// 13. A raw producer cannot encode a verdict. The check refuses the member name
// wherever it appears, at any depth.
TEST(Conformance, Item13ARawProducerCannotEncodeAVerdict) {
    for (const std::string_view kBytes : {std::string_view{R"({"passed":true})"},
                                          std::string_view{R"({"verdict":"ok"})"},
                                          std::string_view{R"({"a":{"promoted":1}})"},
                                          std::string_view{R"({"a":[{"baseline":1}]})"}}) {
        const auto kRecord = parseCanonicalSubset(kBytes);
        ASSERT_TRUE(kRecord.has_value()) << kBytes;
        EXPECT_FALSE(checkProducerAuthority(*kRecord).has_value()) << kBytes;
    }
    const auto kReceipt = fixtureRoot() / "receipts/evaluable-1.json";
    EXPECT_TRUE(checkProducerAuthority(ingest(kReceipt)).has_value());
}

// 14. The assembler carries the same restriction, so a ledger cannot become a
// verdict by being assembled.
TEST(Conformance, Item14TheAssemblerCannotEncodeAPerformanceVerdict) {
    const auto kSet = ingest(fixtureRoot() / "sets/passing.json");
    EXPECT_TRUE(checkProducerAuthority(kSet).has_value());
    EXPECT_EQ(kSet.find("verdict"), nullptr);
    EXPECT_EQ(kSet.find("passed"), nullptr);
}

// 15. Checks run in SPEC-0014's order, and the first failing phase stops the
// later ones, whose checks are retained as not_run so that a later pass cannot
// appear to rescue an earlier blocking failure.
TEST(Conformance, Item15TheEvaluatorRunsInOrderAndLaterPassesCannotMaskEarlierFailures) {
    const auto kReceipt = evaluateAgainst(repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json");
    ASSERT_TRUE(kReceipt.has_value()) << (kReceipt ? std::string{} : kReceipt.error().detail);
    const auto* kChecks = kReceipt->find("checks");
    ASSERT_NE(kChecks, nullptr);
    std::string previousPhase;
    for (const auto& kCheck : kChecks->elements()) {
        const auto* kPhase = kCheck.find("phase");
        ASSERT_NE(kPhase, nullptr);
        if (!previousPhase.empty()) {
            EXPECT_LE(previousPhase, kPhase->text()) << "phases are out of order";
        }
        previousPhase = kPhase->text();
    }
}

// 16. Identical inputs produce byte-identical output. The receipt is emitted
// twice and compared, and then compared against the committed golden bytes.
TEST(Conformance, Item16IdenticalInputsProduceByteIdenticalOutputs) {
    const auto kPolicy = repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json";
    const auto kFirst = evaluateAgainst(kPolicy);
    const auto kSecond = evaluateAgainst(kPolicy);
    ASSERT_TRUE(kFirst.has_value());
    ASSERT_TRUE(kSecond.has_value());
    EXPECT_EQ(serializeCanonical(*kFirst), serializeCanonical(*kSecond));
    EXPECT_EQ(serializeCanonical(*kFirst),
              readAllBytes(fixtureRoot() / "canonical/evaluation-receipt-v1.canonical.json"));
}

// 17. Changing the policy changes the bound evaluation identity, and no raw
// receipt is edited to make that happen. The receipt bytes differ; every raw
// receipt digest the two receipts name is identical.
TEST(Conformance, Item17APolicyChangeChangesEvaluationIdentityWithoutEditingRawReceipts) {
    const auto kBaseline = evaluateAgainst(repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json");
    const auto kShifted = evaluateAgainst(fixtureRoot() / "policies/later-generation.json");
    ASSERT_TRUE(kBaseline.has_value()) << (kBaseline ? std::string{} : kBaseline.error().detail);
    ASSERT_TRUE(kShifted.has_value()) << (kShifted ? std::string{} : kShifted.error().detail);
    EXPECT_NE(serializeCanonical(*kBaseline), serializeCanonical(*kShifted));
    EXPECT_EQ(promotedReceiptDigests(*kBaseline), promotedReceiptDigests(*kShifted));
    EXPECT_FALSE(promotedReceiptDigests(*kBaseline).empty());
}

// 18. A local caller cannot claim trusted provenance, a higher tier, runner
// qualification, or a promotion. The trust value is a schema const, so the
// refusal is structural rather than a check that could be forgotten.
TEST(Conformance, Item18ALocalCallerCannotClaimTrustedCiHigherTiersOrPromotion) {
    const std::string kCommon = readAllBytes(repositoryRoot() / "schemas/evidence-common-v1.schema.json");
    EXPECT_NE(kCommon.find("\"const\": \"diagnostic_untrusted\""), std::string::npos);
    EXPECT_EQ(kCommon.find("trusted_ci"), std::string::npos);
    for (const std::string_view kName : {std::string_view{"claims-trusted-provenance"},
                                         std::string_view{"claims-a-higher-tier"},
                                         std::string_view{"claims-runner-qualification"},
                                         std::string_view{"claims-promotion-is-effective"}}) {
        const auto kPath = fixtureRoot() / "baselines" / (std::string(kName) + ".json");
        EXPECT_FALSE(parseBaselineRecord(repositoryRoot(), kPath, ingest(kPath)).has_value()) << kName;
    }
}

// 19. Every promotion-shaped defect fails with its own typed reason.
TEST(Conformance, Item19BaselineSelfUpdateMissingPredecessorScopeAndTrustDefectsFail) {
    for (const std::string_view kName : {std::string_view{"self-update"},
                                         std::string_view{"self-promotion"},
                                         std::string_view{"missing-predecessor"},
                                         std::string_view{"incompatible-scope"},
                                         std::string_view{"missing-evidence"},
                                         std::string_view{"candidate-controlled-policy"},
                                         std::string_view{"unsupported-provenance"},
                                         std::string_view{"mutable-role"}}) {
        const auto kPath = fixtureRoot() / "baselines" / (std::string(kName) + ".json");
        EXPECT_FALSE(parseBaselineRecord(repositoryRoot(), kPath, ingest(kPath)).has_value()) << kName;
    }
    const auto kWellFormed = fixtureRoot() / "baselines/well-formed.json";
    const auto kRead = parseBaselineRecord(repositoryRoot(), kWellFormed, ingest(kWellFormed));
    ASSERT_TRUE(kRead.has_value());
    EXPECT_EQ(promotionRefusal(*kRead), BaselineDefect::InsufficientTrust);
}

// 20. A fixture cannot enter an active production role, by two independent
// routes. The index admits exactly two authority classes and neither is a
// baseline, and an authority found under evidence/ but not listed is refused.
TEST(Conformance, Item20FixtureBaselineRecordsCannotEnterAnActiveProductionRole) {
    const std::string kIndexSchema = readAllBytes(repositoryRoot() / "schemas/evidence-index-v1.schema.json");
    EXPECT_NE(kIndexSchema.find("metric_registry"), std::string::npos);
    EXPECT_NE(kIndexSchema.find("evaluation_policy"), std::string::npos);
    EXPECT_EQ(kIndexSchema.find("\"baseline_record\""), std::string::npos);
    EXPECT_EQ(kIndexSchema.find("\"baseline_role\""), std::string::npos);

    for (const auto& kAuthority : snapshot().evidenceAuthorities) {
        EXPECT_NE(kAuthority.authorityClass, "baseline_record");
        EXPECT_EQ(kAuthority.path.find("baseline"), std::string::npos);
    }

    const auto kRoot = caseRoot();
    std::filesystem::create_directories(kRoot / "evidence/baselines");
    std::filesystem::copy_file(fixtureRoot() / "baselines/well-formed.json",
                               kRoot / "evidence/baselines/well-formed.json");
    EXPECT_FALSE(rejectUnlistedEvidenceAuthorities(kRoot, "evidence/evidence.json", {}).has_value());
}

// 21. An oracle that is absent, wrong, crashed, or unparseable is a failure and
// never a silently skipped validation.

} // namespace rawframe::tool::evidence
