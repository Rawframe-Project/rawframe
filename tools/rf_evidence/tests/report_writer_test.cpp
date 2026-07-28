#include "report_writer.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

namespace rawframe::tool::evidence {

namespace {

std::string readAllBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream content;
    content << input.rdbuf();
    return std::move(content).str();
}

} // namespace

TEST(ReportWriter, RejectsPathOutsideReportRoot) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveReportPath(kRoot, "out/build/report.json");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

TEST(ReportWriter, RejectsParentTraversal) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveReportPath(kRoot, "out/reports/task-0001/../../../evil.json");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

TEST(ReportWriter, RejectsNonJsonReport) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveReportPath(kRoot, "out/reports/task-0001/windows-x86_64/report.exe");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

TEST(ReportWriter, RejectsAbsolutePath) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveReportPath(kRoot, "/out/reports/task-0001/report.json");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

TEST(ReportWriter, WritesDeterministicBytesAtomically) {
    const std::filesystem::path kOutputRoot = RAWFRAME_TEST_OUTPUT_ROOT;
    const auto kReportPath = kOutputRoot / "report_writer" / "probe.json";
    std::filesystem::remove_all(kOutputRoot / "report_writer");

    const std::string kContent = "{\"schemaVersion\":1,\"operation\":\"probe\"}\n";
    auto first = writeReportAtomically(kReportPath, kContent);
    ASSERT_TRUE(first.has_value()) << first.error().message;
    auto second = writeReportAtomically(kReportPath, kContent);
    ASSERT_TRUE(second.has_value()) << second.error().message;

    EXPECT_EQ(readAllBytes(kReportPath), kContent);
    EXPECT_FALSE(std::filesystem::exists(kReportPath.parent_path() / "probe.json.tmp"));
}

TEST(ReportWriter, BuildsDeterministicGraphReport) {
    RepositorySnapshot snapshot;
    snapshot.tools.push_back(ToolInfo{
        .id = "rawframe.tool.evidence",
        .manifestPath = "tools/rf_evidence/tool.json",
        .owner = "rawframe.build_engineering",
        .cmakeTarget = "rawframe_tool_rf_evidence",
        .thirdPartyDependencies = {"library.openssl", "library.simdjson"},
        .managedToolDependencies = {"tool.jsonschema_oracle"},
    });
    const auto kFirst = buildRepositoryGraphReport(snapshot);
    const auto kSecond = buildRepositoryGraphReport(snapshot);
    EXPECT_EQ(kFirst, kSecond);
    EXPECT_NE(kFirst.find("\"productionModuleCount\":0"), std::string::npos);
    EXPECT_NE(kFirst.find("rawframe_tool_rf_evidence"), std::string::npos);
    EXPECT_EQ(kFirst.back(), '\n');
}

} // namespace rawframe::tool::evidence
