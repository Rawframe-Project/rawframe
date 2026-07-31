#include "requirements.h"
#include "verify_fixture.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace rawframe::tool::verify {

namespace {

constexpr std::string_view kInventory = R"({
  "schemaVersion": 1,
  "criteria": [
    {"id": "DOC-0001:bound", "text": "A criterion a test discharges.", "discharge": "automated"},
    {"id": "DOC-0001:unbound", "text": "A criterion no test discharges.", "discharge": "automated"},
    {"id": "DOC-0001:by-hand", "text": "A criterion no automated test can reach.", "discharge": "manual",
     "procedure": "A reviewer reads the change and records the result."}
  ]
})";

constexpr std::string_view kTestReport = R"({
  "tests": 3,
  "testsuites": [
    {"name": "Suite", "testsuite": [
      {"name": "First", "classname": "Suite", "requirement": "DOC-0001:bound"},
      {"name": "Second", "classname": "Suite", "requirement": " DOC-0001:bound , DOC-0001:invented "},
      {"name": "Third", "classname": "Suite"}
    ]}
  ]
})";

std::vector<DeclaredCriterion> inventoryFrom(const testing::RepositoryFixture& fixture, std::string_view document) {
    fixture.write("out/criteria.json", document);
    auto declared = readCriteriaInventory(fixture.root() / "out/criteria.json");
    EXPECT_TRUE(declared.has_value()) << declared.error().message;
    return declared.value_or(std::vector<DeclaredCriterion>{});
}

} // namespace

TEST(Requirements, ReadsTheDeclaredInventory) {
    const testing::RepositoryFixture kFixture("requirements_inventory");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    ASSERT_EQ(kDeclared.size(), 3U);
    EXPECT_EQ(kDeclared.at(0).id, "DOC-0001:bound");
    EXPECT_EQ(kDeclared.at(2).discharge, DischargeKind::Manual);
    EXPECT_FALSE(kDeclared.at(2).procedure.empty());
}

TEST(Requirements, RejectsAnInventoryThatIsNotOne) {
    const testing::RepositoryFixture kFixture("requirements_bad_inventory");
    const std::vector<std::string_view> kCases{
        R"({"schemaVersion": 1})",
        R"({"criteria": [{"text": "no id", "discharge": "automated"}]})",
        R"({"criteria": [{"id": "no-colon", "text": "t", "discharge": "automated"}]})",
        R"({"criteria": [{"id": "A:one", "text": "t", "discharge": "sometimes"}]})",
        R"({"criteria": [{"id": "A:one", "text": "t", "discharge": "manual"}]})",
        R"({"criteria": [{"id": "A:one", "text": "t", "discharge": "manual", "procedure": ""}]})",
        R"({"criteria": [{"id": "A:one", "text": "t", "discharge": "automated"},
                          {"id": "A:one", "text": "again", "discharge": "automated"}]})",
    };
    for (const auto& document : kCases) {
        kFixture.write("out/criteria.json", document);
        auto declared = readCriteriaInventory(kFixture.root() / "out/criteria.json");
        ASSERT_FALSE(declared.has_value()) << document;
        EXPECT_EQ(declared.error().code, FailureCode::InvalidJson);
    }
}

TEST(Requirements, RejectsAnInventoryFileThatIsNotThere) {
    const testing::RepositoryFixture kFixture("requirements_absent_inventory");
    auto declared = readCriteriaInventory(kFixture.root() / "out/absent.json");
    ASSERT_FALSE(declared.has_value());
    EXPECT_EQ(declared.error().code, FailureCode::MissingInput);
}

TEST(Requirements, GeneratesTheBindingsFromTheTestsThatExecuted) {
    RecordProperty("requirement",
                   "STD-0007:requirements-report-is-generated-from-executed-tests,"
                   "STD-0007:unbound-criteria-are-visible-and-counted");
    const testing::RepositoryFixture kFixture("requirements_report");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    kFixture.write("out/report.json", kTestReport);

    auto report = buildRequirementsReport(kDeclared, {kFixture.root() / "out/report.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->testsRead, 3U);
    EXPECT_EQ(report->bindingsRead, 3U);

    ASSERT_EQ(report->bound.size(), 1U);
    EXPECT_EQ(report->bound.at(0).criterionId, "DOC-0001:bound");
    EXPECT_EQ(report->bound.at(0).tests, (std::vector<std::string>{"Suite.First", "Suite.Second"}));

    ASSERT_EQ(report->unbound.size(), 1U);
    EXPECT_EQ(report->unbound.at(0).id, "DOC-0001:unbound");

    ASSERT_EQ(report->manual.size(), 1U);
    EXPECT_EQ(report->manual.at(0).id, "DOC-0001:by-hand");
}

TEST(Requirements, ReportsATestThatBindsACriterionTheInventoryDoesNotDeclare) {
    const testing::RepositoryFixture kFixture("requirements_drift");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    kFixture.write("out/report.json", kTestReport);

    auto report = buildRequirementsReport(kDeclared, {kFixture.root() / "out/report.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    ASSERT_EQ(report->undeclared.size(), 1U);
    EXPECT_EQ(report->undeclared.at(0).criterionId, "DOC-0001:invented");
    ASSERT_EQ(report->findings.findings.size(), 1U);
    EXPECT_EQ(report->findings.findings.at(0).ruleId, kRuleUndeclaredCriterion);
}

TEST(Requirements, ReadsMoreThanOneTestReport) {
    const testing::RepositoryFixture kFixture("requirements_two_reports");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    kFixture.write("out/first.json",
                   R"({"testsuites":[{"testsuite":[{"name":"A","classname":"S","requirement":"DOC-0001:bound"}]}]})");
    kFixture.write("out/second.json",
                   R"({"testsuites":[{"testsuite":[{"name":"B","classname":"S","requirement":"DOC-0001:unbound"}]}]})");

    auto report =
        buildRequirementsReport(kDeclared, {kFixture.root() / "out/first.json", kFixture.root() / "out/second.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->bound.size(), 2U);
    EXPECT_TRUE(report->unbound.empty());
}

TEST(Requirements, IgnoresASuiteWithNoTestCaseList) {
    const testing::RepositoryFixture kFixture("requirements_empty_suite");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    kFixture.write("out/report.json", R"({"testsuites":[{"name":"Empty"}]})");
    auto report = buildRequirementsReport(kDeclared, {kFixture.root() / "out/report.json"});
    ASSERT_TRUE(report.has_value()) << report.error().message;
    EXPECT_EQ(report->testsRead, 0U);
    EXPECT_EQ(report->bound.size(), 0U);
}

TEST(Requirements, RejectsADocumentThatIsNotAGoogleTestReport) {
    const testing::RepositoryFixture kFixture("requirements_bad_report");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    const std::vector<std::string_view> kCases{
        R"({"tests": 1})",
        R"({"testsuites":[{"testsuite":[7]}]})",
        R"({"testsuites":[{"testsuite":[{"name":"A","classname":"S","requirement":9}]}]})",
        R"({"testsuites":[{"testsuite":[{"classname":"S","requirement":"DOC-0001:bound"}]}]})",
    };
    for (const auto& document : kCases) {
        kFixture.write("out/report.json", document);
        auto report = buildRequirementsReport(kDeclared, {kFixture.root() / "out/report.json"});
        ASSERT_FALSE(report.has_value()) << document;
        EXPECT_EQ(report.error().code, FailureCode::InvalidJson);
    }
}

TEST(Requirements, RefusesToReportWithNoTestReportAtAll) {
    const testing::RepositoryFixture kFixture("requirements_no_report");
    const auto kDeclared = inventoryFrom(kFixture, kInventory);
    auto report = buildRequirementsReport(kDeclared, {});
    ASSERT_FALSE(report.has_value());
    EXPECT_EQ(report.error().code, FailureCode::InvalidArguments);
}

TEST(Requirements, ReadsTheRepositoryInventoryItself) {
    RecordProperty("requirement", "STD-0007:unbound-criteria-are-visible-and-counted");
    auto declared =
        readCriteriaInventory(testing::repositoryRoot() / "tools/rf_verify/criteria/acceptance-criteria.json");
    ASSERT_TRUE(declared.has_value()) << declared.error().message;
    EXPECT_FALSE(declared->empty());
    for (const auto& criterion : *declared) {
        EXPECT_FALSE(criterion.text.empty()) << criterion.id;
        if (criterion.discharge == DischargeKind::Manual) {
            EXPECT_FALSE(criterion.procedure.empty()) << criterion.id;
        }
    }
}

} // namespace rawframe::tool::verify
