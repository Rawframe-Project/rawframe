#include "canonical_json.h"
#include "evaluation_policy.h"
#include "metric_registry.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

RecordResult<EvaluationPolicy> loadPolicy(const std::filesystem::path& path) {
    auto record = ingestCanonicalBytes(readBytes(path));
    if (!record) {
        return std::unexpected(record.error());
    }
    return parseEvaluationPolicy(repositoryRoot(), path, *record);
}

RecordResult<MetricRegistry> loadRegistry(const std::filesystem::path& path) {
    auto record = ingestCanonicalBytes(readBytes(path));
    if (!record) {
        return std::unexpected(record.error());
    }
    return parseMetricRegistry(repositoryRoot(), path, *record);
}

RecordResult<EvaluationPolicy> policyFixture(std::string_view relative) {
    return loadPolicy(fixture(relative));
}

RecordResult<MetricRegistry> registryFixture(std::string_view relative) {
    return loadRegistry(fixture(relative));
}

std::filesystem::path maintainedPolicy() {
    return repositoryRoot() / "evidence/policies/tier0-evaluation-policy-v1.json";
}

std::filesystem::path maintainedRegistry() {
    return repositoryRoot() / "evidence/registries/metric-registry-v1.json";
}

std::string policyWithBound(std::string_view literal) {
    std::string bytes = R"({"entries":[{"bound":{"scaleExponent":0,"value":)";
    bytes += literal;
    bytes += R"(},"checkClass":"correctness","comparison":"at_most",)";
    bytes += R"("metricGeneration":1,"metricId":"harness.workload_failure.count","policyKey":"generated_key"}],)";
    bytes += R"("metricRegistryGeneration":1,"policyGeneration":1,"recordKind":"evaluation_policy",)";
    bytes += R"("schemaVersion":1,"tier":"tier_0","trust":{"provenance":"diagnostic_untrusted"}})";
    return bytes;
}

void expectPolicyRejection(const RecordResult<EvaluationPolicy>& result, RecordRejection rejection) {
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().rejection, rejection) << result.error().detail;
}

void expectMalformed(std::string_view bytes) {
    auto record = ingestCanonicalBytes(bytes);
    ASSERT_FALSE(record.has_value());
    EXPECT_EQ(record.error().rejection, RecordRejection::MalformedInput);
}

// Resolving the maintained pair is the anchor for every binding rejection.
//
// A bound entry is a pair of non-owning views into the policy and the registry,
// so all three travel together. Returning the binding by itself would return
// pointers into two objects destroyed on the way out, and a test that reads
// freed memory passes for as long as the bytes happen to survive, which is most
// of the time and never all of it.
struct MaintainedBinding {
    EvaluationPolicy policy;
    MetricRegistry registry;
    std::vector<BoundPolicyEntry> bound;
};

RecordResult<MaintainedBinding> bindMaintained() {
    auto policy = loadPolicy(maintainedPolicy());
    EXPECT_TRUE(policy.has_value());
    auto registry = loadRegistry(maintainedRegistry());
    EXPECT_TRUE(registry.has_value());
    if (!policy || !registry) {
        return std::unexpected(RecordFailure{RecordRejection::SchemaInvalid, "the maintained pair did not load"});
    }
    // Bound after the pair is in its final home, and moved out as a whole
    // afterwards. Moving a vector carries its buffer rather than its elements,
    // so the addresses the binding holds survive the move that returns it.
    MaintainedBinding result{std::move(*policy), std::move(*registry), {}};
    auto bound = bindPolicyToRegistry(result.policy, result.registry);
    if (!bound) {
        return std::unexpected(bound.error());
    }
    result.bound = std::move(*bound);
    return result;
}

} // namespace

TEST(EvaluationPolicy, LoadsTheMaintainedPolicyExactlyAsCommitted) {
    auto policy = loadPolicy(maintainedPolicy());
    ASSERT_TRUE(policy.has_value());
    EXPECT_EQ(policy->policyGeneration, 1);
    EXPECT_EQ(policy->metricRegistryGeneration, 1);
    EXPECT_EQ(policy->tier, kTier0);
    EXPECT_EQ(policy->entries.size(), 5U);
}

TEST(EvaluationPolicy, BindsTheMaintainedPairCompletely) {
    auto bound = bindMaintained();
    ASSERT_TRUE(bound.has_value());
    ASSERT_EQ(bound->bound.size(), 5U);
    for (const auto& entry : bound->bound) {
        ASSERT_NE(entry.entry, nullptr);
        ASSERT_NE(entry.metric, nullptr);
        EXPECT_EQ(entry.metric->stability, MetricStability::Stable);
        EXPECT_EQ(entry.boundScaleExponent, entry.metric->scaleExponent);
    }
}

TEST(EvaluationPolicy, RefusesAnEntryBindingAnUndeclaredMetric) {
    auto policy = policyFixture("policies/unknown-metric.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = loadRegistry(maintainedRegistry());
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error().rejection, RecordRejection::SchemaInvalid);
}

TEST(EvaluationPolicy, RefusesAnEntryBindingTheRightNameAtTheWrongGeneration) {
    auto policy = policyFixture("policies/wrong-metric-generation.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = loadRegistry(maintainedRegistry());
    ASSERT_TRUE(registry.has_value());
    EXPECT_FALSE(bindPolicyToRegistry(*policy, *registry).has_value());
}

TEST(EvaluationPolicy, RefusesAPolicyWrittenAgainstAnotherRegistryGeneration) {
    auto policy = policyFixture("policies/wrong-registry-generation.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = loadRegistry(maintainedRegistry());
    ASSERT_TRUE(registry.has_value());
    EXPECT_FALSE(bindPolicyToRegistry(*policy, *registry).has_value());
}

TEST(EvaluationPolicy, RefusesAnEntryBindingADiagnosticMetric) {
    auto policy = policyFixture("policies/binds-a-diagnostic-metric.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = registryFixture("registries/diagnostic-metric.json");
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_FALSE(bound.has_value());
    EXPECT_NE(bound.error().detail.find("diagnostic"), std::string::npos);
}

TEST(EvaluationPolicy, RefusesATierZeroCheckAttachedToAPerformanceObjective) {
    auto policy = policyFixture("policies/binds-a-performance-objective.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = loadRegistry(maintainedRegistry());
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_FALSE(bound.has_value());
    EXPECT_NE(bound.error().detail.find("performance_objective"), std::string::npos);
}

TEST(EvaluationPolicy, RefusesTheSamePolicyKeyTwice) {
    expectPolicyRejection(policyFixture("policies/duplicate-key.json"), RecordRejection::SchemaInvalid);
}

TEST(EvaluationPolicy, RefusesAFractionalBound) {
    expectMalformed(policyWithBound("0.5"));
}

TEST(EvaluationPolicy, RefusesAnExponentFormBound) {
    expectMalformed(policyWithBound("5e0"));
}

TEST(EvaluationPolicy, RefusesANotANumberBound) {
    expectMalformed(policyWithBound("NaN"));
}

TEST(EvaluationPolicy, RefusesAnInfiniteBound) {
    expectMalformed(policyWithBound("Infinity"));
}

TEST(EvaluationPolicy, RefusesANegativeZeroBound) {
    expectMalformed(policyWithBound("-0"));
}

TEST(EvaluationPolicy, RefusesABoundClaimingACanonicalResult) {
    expectPolicyRejection(policyFixture("policies/claims-a-canonical-result.json"), RecordRejection::SchemaInvalid);
}

TEST(EvaluationPolicy, RefusesARelativeComparison) {
    expectPolicyRejection(policyFixture("policies/compares-relatively.json"), RecordRejection::SchemaInvalid);
}

TEST(EvaluationPolicy, RefusesAQualificationResult) {
    expectPolicyRejection(policyFixture("policies/claims-a-qualification.json"), RecordRejection::SchemaInvalid);
}

TEST(EvaluationPolicy, RefusesTrustedProvenance) {
    expectPolicyRejection(policyFixture("policies/claims-trusted-provenance.json"), RecordRejection::SchemaInvalid);
}

TEST(EvaluationPolicy, RefusesAPromotion) {
    expectPolicyRejection(policyFixture("policies/claims-a-promotion.json"), RecordRejection::SchemaInvalid);
}

// Decision 9. The registry states the direction and the rounding; the policy
// states a bound in whatever scale reads well to a human. Where those two meet
// is asserted here rather than left to whoever writes the evaluator.
TEST(EvaluationPolicy, CarriesAMillisecondBoundToTheMetricScaleExactly) {
    auto policy = policyFixture("policies/bound-in-milliseconds.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = registryFixture("registries/scaled-reject-inexact.json");
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_TRUE(bound.has_value());
    ASSERT_EQ(bound->size(), 1U);
    EXPECT_EQ(bound->front().boundValue, 8'000'000);
    EXPECT_EQ(bound->front().boundScaleExponent, 0);
}

TEST(EvaluationPolicy, RefusesABoundThatCannotReachTheMetricScaleExactly) {
    auto policy = policyFixture("policies/bound-with-a-remainder.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = registryFixture("registries/scaled-reject-inexact.json");
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_FALSE(bound.has_value());
    EXPECT_NE(bound.error().detail.find("not exact"), std::string::npos);
}

TEST(EvaluationPolicy, LeavesTheBoundWhereItWasWrittenWhenTheObservationIsTheSideThatMoves) {
    auto policy = policyFixture("policies/bound-in-milliseconds.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = registryFixture("registries/scaled-observation-moves.json");
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_TRUE(bound.has_value());
    ASSERT_EQ(bound->size(), 1U);
    EXPECT_EQ(bound->front().boundValue, 8);
    EXPECT_EQ(bound->front().boundScaleExponent, 6);
}

TEST(EvaluationPolicy, RefusesABoundThatCannotReachTheMetricScaleAtAll) {
    auto policy = policyFixture("policies/bound-beyond-the-safe-range.json");
    ASSERT_TRUE(policy.has_value());
    auto registry = registryFixture("registries/scaled-reject-inexact.json");
    ASSERT_TRUE(registry.has_value());
    auto bound = bindPolicyToRegistry(*policy, *registry);
    ASSERT_FALSE(bound.has_value());
    EXPECT_EQ(bound.error().rejection, RecordRejection::LimitExceeded);
}

} // namespace rawframe::tool::evidence
