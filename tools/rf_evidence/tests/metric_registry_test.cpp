#include "canonical_json.h"
#include "file_reader.h"
#include "metric_registry.h"

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

std::filesystem::path fixture(std::string_view relative) {
    return repositoryRoot() / "tools/rf_evidence/tests/fixtures/evidence" / relative;
}

std::string readBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    EXPECT_TRUE(input.is_open()) << "missing file: " << path.generic_string();
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

// The whole gate, exactly as the loader runs it: canonical ingestion, then the
// record checks, then the semantic ones. A test that skipped ingestion would
// prove the parser accepts something the tool never reaches.
RecordResult<MetricRegistry> load(const std::filesystem::path& path) {
    auto record = ingestCanonicalBytes(readBytes(path));
    if (!record) {
        return std::unexpected(record.error());
    }
    return parseMetricRegistry(repositoryRoot(), path, *record);
}

RecordResult<MetricRegistry> loadFixture(std::string_view relative) {
    return load(fixture(relative));
}

std::filesystem::path maintainedRegistry() {
    return repositoryRoot() / "evidence/registries/metric-registry-v1.json";
}

// Bulk-limit cases are written at run time rather than committed. A megabyte of
// generated fixture in the repository would be maintained material that nobody
// maintains, and the limits it proves are about counts, not content.
std::filesystem::path writeGenerated(std::string_view name, std::string_view bytes) {
    const std::filesystem::path kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "metric_registry";
    std::filesystem::create_directories(kRoot);
    const std::filesystem::path kPath = kRoot / std::filesystem::path(std::string(name));
    std::ofstream output(kPath, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    output.close();
    return kPath;
}

std::string registryOf(std::size_t metricCount) {
    std::string bytes = R"({"metrics":[)";
    for (std::size_t index = 0; index < metricCount; ++index) {
        if (index > 0) {
            bytes += ",";
        }
        bytes += R"({"budgetClass":"hard_ceiling","metricGeneration":1,"metricId":"generated.metric_)";
        bytes += std::to_string(index);
        bytes += R"(","owner":"evidence_harness","polarity":"lower_is_better","queryId":"generated.query.v1",)";
        bytes += R"("rescaling":{"direction":"bound_to_observation","rounding":"reject_inexact"},)";
        bytes += R"("sampling":{"blockLength":1,"kind":"per_run"},"scaleExponent":0,"scope":"run",)";
        bytes += R"("stability":"stable","statistic":"count","unit":"count"})";
    }
    bytes += R"(],"recordKind":"metric_registry","registryGeneration":1,"schemaVersion":1})";
    return bytes;
}

// One rejected lexical form, expressed as the registry a caller would hand
// over. The accepted subset has no floating-point kind at all, so each of these
// dies before any registry semantics exist.
std::string registryWithBlockLength(std::string_view literal) {
    std::string bytes = R"({"metrics":[{"budgetClass":"hard_ceiling","metricGeneration":1,)";
    bytes += R"("metricId":"generated.metric","owner":"evidence_harness","polarity":"lower_is_better",)";
    bytes += R"("queryId":"generated.query.v1",)";
    bytes += R"("rescaling":{"direction":"bound_to_observation","rounding":"reject_inexact"},)";
    bytes += R"("sampling":{"blockLength":)";
    bytes += literal;
    bytes += R"(,"kind":"per_run"},"scaleExponent":0,"scope":"run","stability":"stable",)";
    bytes += R"("statistic":"count","unit":"count"}],"recordKind":"metric_registry",)";
    bytes += R"("registryGeneration":1,"schemaVersion":1})";
    return bytes;
}

void expectRejection(const RecordResult<MetricRegistry>& result, RecordRejection rejection) {
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().rejection, rejection) << result.error().detail;
}

void expectMalformed(std::string_view bytes) {
    auto record = ingestCanonicalBytes(bytes);
    ASSERT_FALSE(record.has_value());
    EXPECT_EQ(record.error().rejection, RecordRejection::MalformedInput);
}

} // namespace

// The anchor. Every rejection below is a mutation of material that loads, so a
// suite that started failing everything would be visibly broken rather than
// quietly vacuous.
TEST(MetricRegistry, LoadsTheMaintainedRegistryExactlyAsCommitted) {
    auto registry = load(maintainedRegistry());
    ASSERT_TRUE(registry.has_value());
    EXPECT_EQ(registry->registryGeneration, 1);
    EXPECT_EQ(registry->metrics.size(), 10U);
    const MetricEntry* entry = registry->find("harness.workload_failure.count", 1);
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->stability, MetricStability::Stable);
    EXPECT_EQ(entry->polarity, MetricPolarity::LowerIsBetter);
    EXPECT_EQ(entry->budgetClass, "hard_ceiling");
    EXPECT_EQ(entry->unit, "count");
}

TEST(MetricRegistry, RefusesTwoEntriesSharingIdentifierAndGeneration) {
    expectRejection(loadFixture("registries/duplicate-identity.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, AdmitsOneIdentifierAtTwoGenerationsAndKeepsThemApart) {
    auto registry = loadFixture("registries/two-generations.json");
    ASSERT_TRUE(registry.has_value());
    ASSERT_EQ(registry->metrics.size(), 2U);
    const MetricEntry* first = registry->find("harness.assertion_failure.count", 1);
    const MetricEntry* second = registry->find("harness.assertion_failure.count", 2);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_NE(first, second);
    EXPECT_EQ(first->unit, "count");
    EXPECT_EQ(second->unit, "nanosecond");
}

TEST(MetricRegistry, ResolvesNothingByIdentifierAlone) {
    auto registry = load(maintainedRegistry());
    ASSERT_TRUE(registry.has_value());
    EXPECT_EQ(registry->find("harness.workload_failure.count", 2), nullptr);
    EXPECT_EQ(registry->find("harness.workload_failure.count", 0), nullptr);
}

TEST(MetricRegistry, RefusesAFractionalValue) {
    expectMalformed(registryWithBlockLength("1.5"));
}

TEST(MetricRegistry, RefusesAnExponentForm) {
    expectMalformed(registryWithBlockLength("1e3"));
}

TEST(MetricRegistry, RefusesNotANumber) {
    expectMalformed(registryWithBlockLength("NaN"));
}

TEST(MetricRegistry, RefusesAnInfinity) {
    expectMalformed(registryWithBlockLength("Infinity"));
}

TEST(MetricRegistry, RefusesANegativeZero) {
    expectMalformed(registryWithBlockLength("-0"));
}

TEST(MetricRegistry, AdmitsBothEndsOfTheScaleRange) {
    EXPECT_TRUE(loadFixture("registries/scale-minimum.json").has_value());
    EXPECT_TRUE(loadFixture("registries/scale-maximum.json").has_value());
}

TEST(MetricRegistry, RefusesAScaleOnePastEitherEnd) {
    expectRejection(loadFixture("registries/scale-below-minimum.json"), RecordRejection::SchemaInvalid);
    expectRejection(loadFixture("registries/scale-above-maximum.json"), RecordRejection::SchemaInvalid);
}

// One past the limit never reaches the schema: the canonical subset itself has
// no value there, so the bytes are refused before anything reads them as a
// registry. That is the earlier and stronger of the two refusals.
TEST(MetricRegistry, AdmitsTheSafeIntegerLimitAndRefusesOnePastIt) {
    EXPECT_TRUE(loadFixture("registries/safe-integer-limit.json").has_value());
    expectRejection(loadFixture("registries/beyond-safe-integer.json"), RecordRejection::LimitExceeded);
}

TEST(MetricRegistry, RefusesAMetricThatOmitsPolarity) {
    expectRejection(loadFixture("registries/missing-polarity.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnUnknownUnit) {
    expectRejection(loadFixture("registries/unknown-unit.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnUnknownStatistic) {
    expectRejection(loadFixture("registries/unknown-statistic.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnUnknownStability) {
    expectRejection(loadFixture("registries/unknown-stability.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnUnknownScope) {
    expectRejection(loadFixture("registries/unknown-scope.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnUnknownBudgetClass) {
    expectRejection(loadFixture("registries/unknown-budget-class.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnUnknownRoundingRule) {
    expectRejection(loadFixture("registries/unknown-rescaling-rounding.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAnOutcomeClaimAnchoredByTheSameShapeWithoutOne) {
    EXPECT_TRUE(loadFixture("registries/benign-sibling.json").has_value());
    expectRejection(loadFixture("registries/outcome-claim.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, AdmitsSixtyFourLabelsAndRefusesSixtyFive) {
    EXPECT_TRUE(loadFixture("registries/label-limit.json").has_value());
    expectRejection(loadFixture("registries/beyond-label-limit.json"), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, AdmitsTheMetricCountLimitAndRefusesOnePastIt) {
    const auto kAtLimit = writeGenerated("at-limit.json", registryOf(kMaximumRegisteredMetrics));
    EXPECT_TRUE(load(kAtLimit).has_value());

    const auto kPastLimit = writeGenerated("past-limit.json", registryOf(kMaximumRegisteredMetrics + 1));
    expectRejection(load(kPastLimit), RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RefusesAMaintainedAuthorityBeyondTheByteCeiling) {
    const std::string kAtLimit(kMaximumRecordBytes, 'x');
    EXPECT_TRUE(readBoundedFile(writeGenerated("at-byte-limit.json", kAtLimit), kMaximumRecordBytes).has_value());

    const std::string kPastLimit(kMaximumRecordBytes + 1, 'x');
    auto refused = readBoundedFile(writeGenerated("past-byte-limit.json", kPastLimit), kMaximumRecordBytes);
    ASSERT_FALSE(refused.has_value());
    EXPECT_EQ(refused.error().code, FailureCode::LimitExceeded);
}

TEST(MetricRegistry, YieldsNoPartialRegistryWhenOneEntryFails) {
    auto registry = loadFixture("registries/unknown-unit.json");
    ASSERT_FALSE(registry.has_value());
    // There is no accessor that could hand back the entries read before the
    // failure, which is the point: rejection produces a rejection and nothing
    // a caller could mistake for a partly loaded authority.
    EXPECT_FALSE(registry.error().detail.empty());
}

TEST(MetricRegistry, WidensAScaleExactly) {
    auto value = rescaleExact(8, 6, 0, RescaleRounding::RejectInexact);
    ASSERT_TRUE(value.has_value());
    EXPECT_EQ(*value, 8'000'000);
}

TEST(MetricRegistry, RefusesToWidenPastTheSafeIntegerRange) {
    auto value = rescaleExact(kMaximumSafeInteger, 3, 0, RescaleRounding::RejectInexact);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().rejection, RecordRejection::LimitExceeded);
}

TEST(MetricRegistry, RefusesAnInexactNarrowingWhenTheMetricSaysSo) {
    auto value = rescaleExact(8'333, 0, 2, RescaleRounding::RejectInexact);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(MetricRegistry, RoundsANarrowingInTheDeclaredDirection) {
    auto down = rescaleExact(8'333, 0, 2, RescaleRounding::TowardNegativeInfinity);
    ASSERT_TRUE(down.has_value());
    EXPECT_EQ(*down, 83);

    auto up = rescaleExact(8'333, 0, 2, RescaleRounding::TowardPositiveInfinity);
    ASSERT_TRUE(up.has_value());
    EXPECT_EQ(*up, 84);
}

TEST(MetricRegistry, RoundsNegativeValuesTowardTheNamedInfinityRatherThanTowardZero) {
    auto down = rescaleExact(-8'333, 0, 2, RescaleRounding::TowardNegativeInfinity);
    ASSERT_TRUE(down.has_value());
    EXPECT_EQ(*down, -84);

    auto up = rescaleExact(-8'333, 0, 2, RescaleRounding::TowardPositiveInfinity);
    ASSERT_TRUE(up.has_value());
    EXPECT_EQ(*up, -83);
}

// The case the declared direction exists for. A ceiling of 8 ms against an
// observation of 8.333 ms is a breach. Moving the bound to the observation's
// scale keeps it one: 8000000 nanoseconds against 8333000. Moving the
// observation to the bound's scale and rounding it down turns 8.333 into 8 and
// makes the breach disappear, which is why the direction is the metric's to
// declare and never the comparison's to pick.
TEST(MetricRegistry, KeepsABreachVisibleWhenTheBoundIsTheSideThatMoves) {
    constexpr std::int64_t kObservationNanoseconds = 8'333'000;
    auto boundAtObservationScale = rescaleExact(8, 6, 0, RescaleRounding::RejectInexact);
    ASSERT_TRUE(boundAtObservationScale.has_value());
    EXPECT_GT(kObservationNanoseconds, *boundAtObservationScale);

    auto observationAtBoundScale = rescaleExact(kObservationNanoseconds, 0, 6, RescaleRounding::TowardNegativeInfinity);
    ASSERT_TRUE(observationAtBoundScale.has_value());
    EXPECT_EQ(*observationAtBoundScale, 8);
    EXPECT_FALSE(*observationAtBoundScale > 8);
}

TEST(MetricRegistry, RefusesAScaleOutsideTheAcceptedRangeBeforeRescaling) {
    auto value = rescaleExact(1, 0, 19, RescaleRounding::RejectInexact);
    ASSERT_FALSE(value.has_value());
    EXPECT_EQ(value.error().rejection, RecordRejection::LimitExceeded);
}

} // namespace rawframe::tool::evidence
