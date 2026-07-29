#include "baseline_record.h"
#include "canonical_json.h"
#include "descriptor.h"
#include "record_gate.h"

#include <array>
#include <cstdint>
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

std::filesystem::path baselineRoot() {
    return repositoryRoot() / "tools/rf_evidence/tests/fixtures/evidence/baselines";
}

// Where the pinned offline schema oracle sits beneath a repository root. The
// tool resolves it the same way, and this restates the one fact a scratch root
// needs rather than exposing the resolver.
std::filesystem::path oracleRelativePath() {
#ifdef _WIN32
    return std::filesystem::path("out/prepared/windows-x86_64/tools/jsonschema/bin/jsonschema.exe");
#else
    return std::filesystem::path("out/prepared/linux-x86_64/tools/jsonschema/bin/jsonschema");
#endif
}

std::string readAllBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing fixture: " << path.generic_string();
    std::ostringstream content;
    content << input.rdbuf();
    return content.str();
}

// A directory of this case's own, named from the case rather than from a
// counter, for the reason the evaluator suite records: each case runs in its
// own process, and a counter would hand every one of them the same path.
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
    const std::filesystem::path kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "bl" / label;
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    return kRoot;
}

RecordResult<BaselineRecord> readFixture(std::string_view name) {
    const std::filesystem::path kPath = baselineRoot() / (std::string(name) + ".json");
    auto parsed = ingestCanonicalBytes(readAllBytes(kPath));
    EXPECT_TRUE(parsed.has_value()) << name;
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return parseBaselineRecord(repositoryRoot(), kPath, *parsed);
}

// The fixture read against a deliberately widened copy of the schema.
//
// Four of the reader's refusals are also schema refusals, and the schema fires
// first, which makes those branches unreachable through the ordinary path. That
// is not a reason to delete them: `checkProducerAuthority` keeps a check the
// schemas already close for exactly this reason, so that widening a schema by
// accident cannot quietly open a door. The difference here is that the second
// line is proven rather than asserted. The schema is copied with one keyword
// renamed to something the validator does not know, which JSON Schema requires
// it to ignore, and the record is read against it. A test failure means the
// reader stopped catching what only it would catch.
//
// The keyword is renamed rather than deleted, and to a name of the same length,
// because a schema with a hole cut in it is a broken document and would be
// refused for being unparseable rather than for being permissive. That refusal
// would look like a pass.
RecordResult<BaselineRecord>
readAgainstWidenedSchema(std::string_view name, std::string_view keyword, std::string_view ignoredKeyword) {
    const std::filesystem::path kRoot = caseRoot();
    std::filesystem::create_directories(kRoot / "schemas");
    for (const auto& kEntry : std::filesystem::directory_iterator(repositoryRoot() / "schemas")) {
        std::filesystem::copy_file(kEntry.path(), kRoot / "schemas" / kEntry.path().filename());
    }
    // The oracle is resolved beneath the root it is given, so a root holding
    // only schemas has no validator and every record read against it would fail
    // for the wrong reason. The pinned executable is copied rather than
    // acquired: this case widens a schema, not the toolchain.
    const std::filesystem::path kOracle = oracleRelativePath();
    std::filesystem::create_directories(kRoot / kOracle.parent_path());
    std::filesystem::copy_file(repositoryRoot() / kOracle, kRoot / kOracle);

    const std::filesystem::path kSchema = kRoot / "schemas" / "baseline-record-v1.schema.json";
    std::string text = readAllBytes(kSchema);
    EXPECT_EQ(keyword.size(), ignoredKeyword.size()) << "the replacement must not change the byte length";
    if (!text.contains(keyword)) {
        EXPECT_TRUE(false) << "the keyword this case widens is gone: " << keyword;
        return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "keyword absent"});
    }
    for (std::size_t at = text.find(keyword); at != std::string::npos; at = text.find(keyword, at + keyword.size())) {
        text.replace(at, keyword.size(), ignoredKeyword);
    }
    {
        std::ofstream output(kSchema, std::ios::binary | std::ios::trunc);
        output << text;
    }

    const std::filesystem::path kFixture = baselineRoot() / (std::string(name) + ".json");
    auto parsed = ingestCanonicalBytes(readAllBytes(kFixture));
    EXPECT_TRUE(parsed.has_value()) << name;
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return parseBaselineRecord(kRoot, kFixture, *parsed);
}

void expectDefect(const RecordResult<BaselineRecord>& result, BaselineDefect defect) {
    ASSERT_FALSE(result.has_value());
    const std::string kExpected = std::string(baselineDefectName(defect)) + ":";
    EXPECT_TRUE(result.error().detail.starts_with(kExpected))
        << "expected " << kExpected << " but got " << result.error().detail;
}

void expectSchemaRefusal(std::string_view name) {
    const auto kResult = readFixture(name);
    ASSERT_FALSE(kResult.has_value()) << name;
    EXPECT_EQ(kResult.error().rejection, RecordRejection::SchemaInvalid);
}

} // namespace

TEST(BaselineRecord, ReadsAWellFormedRecord) {
    const auto kResult = readFixture("well-formed");
    ASSERT_TRUE(kResult.has_value()) << (kResult ? "" : kResult.error().detail);
    EXPECT_EQ(kResult->baselineId, "f1000000-0000-4000-8000-000000000001");
    EXPECT_EQ(kResult->role, BaselineRole::Anchor);
    EXPECT_TRUE(kResult->firstBaseline);
    EXPECT_EQ(kResult->state, BaselineState::Active);
    EXPECT_EQ(kResult->affectedMetrics.size(), 2U);
}

TEST(BaselineRecord, ReadsASupersededRecordThatNamesItsSuccessor) {
    const auto kResult = readFixture("superseded");
    ASSERT_TRUE(kResult.has_value()) << (kResult ? "" : kResult.error().detail);
    EXPECT_FALSE(kResult->firstBaseline);
    EXPECT_EQ(kResult->state, BaselineState::Superseded);
    EXPECT_FALSE(kResult->predecessorDigest.empty());
}

// Reading a record is not promoting one, and this is the case that says so.
// Nothing about the record is consulted to reach the refusal, because there is
// no well-formed record for which a different answer would be correct.
TEST(BaselineRecord, RefusesToPromoteEvenAPerfectlyWellFormedRecord) {
    const auto kResult = readFixture("well-formed");
    ASSERT_TRUE(kResult.has_value());
    EXPECT_EQ(promotionRefusal(*kResult), BaselineDefect::InsufficientTrust);

    const auto kSuperseded = readFixture("superseded");
    ASSERT_TRUE(kSuperseded.has_value());
    EXPECT_EQ(promotionRefusal(*kSuperseded), BaselineDefect::InsufficientTrust);
}

TEST(BaselineRecord, RefusesAPromotionRidingInOnTheChangeItApproves) {
    expectDefect(readFixture("self-update"), BaselineDefect::SelfUpdate);
}

TEST(BaselineRecord, RefusesAReviewThatIsTheChangeItReviewed) {
    expectDefect(readFixture("self-promotion"), BaselineDefect::SelfPromotion);
}

TEST(BaselineRecord, RefusesAStatusThatChangedWithoutASuccessor) {
    expectDefect(readFixture("mutable-role"), BaselineDefect::MutableRole);
}

TEST(BaselineRecord, RefusesAnActiveRecordThatAlreadyNamesASuccessor) {
    expectDefect(readFixture("active-with-successor"), BaselineDefect::MutableRole);
}

TEST(BaselineRecord, RefusesRelativeHeadroomAtATierWithNoQualifiedCell) {
    expectDefect(readFixture("incompatible-scope"), BaselineDefect::IncompatibleScope);
}

TEST(BaselineRecord, RefusesAMarginAgainstAMetricTheRecordDoesNotAffect) {
    expectDefect(readFixture("headroom-out-of-scope"), BaselineDefect::IncompatibleScope);
}

TEST(BaselineRecord, RefusesOneArtifactStandingInForBothHalvesOfTheEvidence) {
    expectDefect(readFixture("missing-evidence"), BaselineDefect::MissingEvidence);
}

TEST(BaselineRecord, RefusesTheCandidatesOwnEvaluationAsItsProtectedReview) {
    expectDefect(readFixture("candidate-controlled-policy"), BaselineDefect::CandidateControlledPolicy);
}

TEST(BaselineRecord, RefusesProvenanceItCannotResolveOffline) {
    expectDefect(readFixture("unsupported-provenance"), BaselineDefect::UnsupportedProvenance);
}

// The four the schema catches first. Each is asserted twice: once that the
// schema refuses it, and once that the reader would refuse it too if the schema
// stopped. A defence with only the first half is a defence that disappears the
// day someone relaxes a constraint for an unrelated reason.
TEST(BaselineRecord, RefusesAChainWithAGapBySchemaAndByReader) {
    expectSchemaRefusal("missing-predecessor");
    expectDefect(readAgainstWidenedSchema("missing-predecessor", "\"oneOf\"", "\"xneOf\""),
                 BaselineDefect::MissingPredecessor);
}

TEST(BaselineRecord, RefusesARecordThatIsBothFirstAndASuccessorBySchemaAndByReader) {
    expectSchemaRefusal("contradictory-chain");
    expectDefect(readAgainstWidenedSchema("contradictory-chain", "\"oneOf\"", "\"xneOf\""),
                 BaselineDefect::MissingPredecessor);
}

TEST(BaselineRecord, RefusesMoreThanSixtyFourAffectedMetricsBySchemaAndByReader) {
    expectSchemaRefusal("too-many-metrics");
    const auto kWidened = readAgainstWidenedSchema("too-many-metrics", "\"maxItems\"", "\"xaxItems\"");
    ASSERT_FALSE(kWidened.has_value());
    EXPECT_EQ(kWidened.error().rejection, RecordRejection::LimitExceeded);
}

TEST(BaselineRecord, RefusesMoreThanThirtyTwoChainEntriesBySchemaAndByReader) {
    expectSchemaRefusal("long-chain");
    const auto kWidened = readAgainstWidenedSchema("long-chain", "\"maxItems\"", "\"xaxItems\"");
    ASSERT_FALSE(kWidened.has_value());
    EXPECT_EQ(kWidened.error().rejection, RecordRejection::LimitExceeded);
}

TEST(BaselineRecord, AcceptsExactlySixtyFourAffectedMetrics) {
    const auto kResult = readFixture("at-metric-limit");
    ASSERT_TRUE(kResult.has_value()) << (kResult ? "" : kResult.error().detail);
    EXPECT_EQ(kResult->affectedMetrics.size(), kMaximumAffectedMetrics);
}

// Every route by which an input member could try to raise trust, tier, or the
// authority that approved it. Each is refused by the schema, which is the
// strongest refusal available: a const cannot be argued with at runtime.
TEST(BaselineRecord, RefusesEveryInputMemberThatWouldRaiseTrustOrTier) {
    for (const std::string_view kName : {std::string_view{"claims-trusted-provenance"},
                                         std::string_view{"claims-a-higher-tier"},
                                         std::string_view{"claims-an-unpassed-verdict"},
                                         std::string_view{"claims-an-agent-approval"},
                                         std::string_view{"claims-an-unknown-role"}}) {
        expectSchemaRefusal(kName);
    }
}

// The claim scope, member by member. A promotion record is exactly the artifact
// that gets quoted out of context, so it argues against that reading in its own
// bytes and a record that stops arguing is refused.
TEST(BaselineRecord, RefusesEveryClaimAValidatedRecordMustNotMake) {
    for (const std::string_view kName : {std::string_view{"claims-promotion-is-effective"},
                                         std::string_view{"claims-an-active-baseline"},
                                         std::string_view{"claims-a-relative-comparison"},
                                         std::string_view{"claims-runner-qualification"},
                                         std::string_view{"claims-performance"}}) {
        expectSchemaRefusal(kName);
    }
}

// The record kind reaches its gate ahead of the producer-authority check, and
// this is why. Held to a producer's restriction, a promotion pointer could not
// exist: it names what was promoted and points at a passing verdict.
TEST(BaselineRecord, CarriesMembersAProducerRecordMayNotCarry) {
    const auto kBytes = readAllBytes(baselineRoot() / "well-formed.json");
    auto parsed = ingestCanonicalBytes(kBytes);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_FALSE(checkProducerAuthority(*parsed).has_value());
    EXPECT_TRUE(parseBaselineRecord(repositoryRoot(), baselineRoot() / "well-formed.json", *parsed).has_value());
}

TEST(BaselineRecord, BindsTheMediaTypeTheGenerationGrammarRequires) {
    EXPECT_EQ(kBaselineRecordMediaType, "application/vnd.rawframe.evidence.baseline-record.v1+json");
    EXPECT_EQ(kBaselineRecordGeneration, 1);
}

} // namespace rawframe::tool::evidence
