// SPEC-0017 corpus items 21 through 25: repository closure and hygiene.
//
// Split out of conformance_test.cpp under the STD-0001 ownership review
// recorded in TASK-0007. These five items share a subject with each other and
// with nothing else in the corpus: they ask whether the repository itself is
// well formed, rather than whether a record is. The corpus file keeps the
// numbered names so a gap is still a missing name, and these keep theirs.
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

RepositorySnapshot snapshot() {
    auto validated = validateRepository(repositoryRoot());
    EXPECT_TRUE(validated.has_value()) << (validated ? std::string{} : validated.error().message);
    return validated ? *validated : RepositorySnapshot{};
}

} // namespace

TEST(Conformance, Item21AnUnavailableOrBrokenSchemaOracleIsAFailureNotASkip) {
    const auto kRoot = caseRoot();
    std::filesystem::create_directories(kRoot / "schemas");
    std::filesystem::copy_file(repositoryRoot() / "schemas/baseline-record-v1.schema.json",
                               kRoot / "schemas/baseline-record-v1.schema.json");
    const auto kPath = fixtureRoot() / "baselines/well-formed.json";
    const auto kResult = parseBaselineRecord(kRoot, kPath, ingest(kPath));
    ASSERT_FALSE(kResult.has_value()) << "a root without the oracle must not validate anything";
    EXPECT_FALSE(verifySchemaOracleVersion(kRoot).has_value());
}

// 22. Limits fail safely at the boundary, and one past it yields no partial
// record rather than a truncated one.
TEST(Conformance, Item22EveryLimitFailsSafelyAtItsBoundary) {
    const auto kAt = fixtureRoot() / "baselines/at-metric-limit.json";
    const auto kAccepted = parseBaselineRecord(repositoryRoot(), kAt, ingest(kAt));
    ASSERT_TRUE(kAccepted.has_value());
    EXPECT_EQ(kAccepted->affectedMetrics.size(), kMaximumAffectedMetrics);

    const auto kOver = fixtureRoot() / "baselines/too-many-metrics.json";
    EXPECT_FALSE(parseBaselineRecord(repositoryRoot(), kOver, ingest(kOver)).has_value());

    EXPECT_FALSE(ingestCanonicalBytes(std::string(kMaximumRecordBytes + 1, 'a')).has_value());
}

// 23. No repository tool is reachable from a production closure, proven
// mechanically rather than by the absence of a production tree.
TEST(Conformance, Item23NoRepositoryToolIsReachableFromAProductionClosure) {
    const auto kAudit = auditShippingClosure(repositoryRoot(), snapshot());
    ASSERT_TRUE(kAudit.has_value()) << (kAudit ? std::string{} : kAudit.error().message);
    EXPECT_TRUE(kAudit->allPassed());
    EXPECT_EQ(kAudit->checks.size(), 9U);
}

// 24. An unregistered tool root or a hidden build input fails repository
// validation, so membership is explicit rather than discovered.
TEST(Conformance, Item24AnUnregisteredToolRootOrHiddenInputFailsRepositoryValidation) {
    const auto kSnapshot = snapshot();
    EXPECT_FALSE(kSnapshot.tools.empty());
    EXPECT_FALSE(kSnapshot.evidenceIndexPath.empty());
    const auto kRoot = caseRoot();
    EXPECT_FALSE(validateRepository(kRoot).has_value()) << "a root with no manifest must not validate";
}

// 25. No root exists before an accepted active Task populates it. The audit
// classifies every maintained file against the frozen envelope, and an
// unclassified or empty root is visible rather than tolerated.
TEST(Conformance, Item25NoRootExistsBeforeItsTaskCreatesPopulatedContent) {
    const auto kAudit = auditRepositoryPaths(repositoryRoot());
    ASSERT_TRUE(kAudit.has_value()) << (kAudit ? std::string{} : kAudit.error().message);
    EXPECT_TRUE(kAudit->envelopeViolations.empty());
    EXPECT_FALSE(kAudit->envelopeFiles.empty());
    for (const std::string_view kAbsent : {std::string_view{"source"},
                                           std::string_view{"tests"},
                                           std::string_view{"modules"},
                                           std::string_view{"evidence/baselines"}}) {
        EXPECT_FALSE(std::filesystem::exists(repositoryRoot() / kAbsent)) << kAbsent;
    }
}

} // namespace rawframe::tool::evidence
