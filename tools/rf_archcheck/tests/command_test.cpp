#include "command.h"
#include "repository_fixture.h"

#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::archcheck {

namespace {

CommandOutput run(const std::vector<std::string>& arguments) {
    std::vector<std::string_view> views;
    views.reserve(arguments.size());
    for (const auto& argument : arguments) {
        views.emplace_back(argument);
    }
    return runCommand(std::span<const std::string_view>(views));
}

std::string readAll(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
}

} // namespace

TEST(Command, ACleanRepositoryExitsZeroAndStillWritesTheDocument) {
    testing::RepositoryFixture fixture("command-clean");
    const CommandOutput kOutput = run({"check_repository",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::Clean) << kOutput.standardError;
    EXPECT_NE(kOutput.standardOutput.find("\"findingCount\": 0"), std::string::npos);
}

TEST(Command, AViolatingRepositoryExitsOneAndSaysWhatItFound) {
    testing::RepositoryFixture fixture("command-findings");
    // A tool manifest nothing lists. RA2006 refuses exactly this.
    fixture.write("tools/stray/tool.json", "{\n  \"id\": \"rawframe.tool.stray\"\n}\n");
    const CommandOutput kOutput = run({"check_repository",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::Findings);
    EXPECT_NE(kOutput.standardOutput.find("RA2006"), std::string::npos);
    EXPECT_NE(kOutput.standardOutput.find("tools/stray/tool.json"), std::string::npos);
}

TEST(Command, AMalformedCorpusExitsThreeRatherThanReportingACleanRepository) {
    testing::RepositoryFixture fixture("command-malformed-corpus");
    fixture.write(testing::RepositoryFixture::corpusRelativePath(), "{ this is not JSON ");
    const CommandOutput kOutput = run({"check_repository",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::InternalError);
    EXPECT_TRUE(kOutput.standardOutput.empty());
}

TEST(Command, AnAbsentRepositoryIndexExitsThreeRatherThanZero) {
    testing::RepositoryFixture fixture("command-absent-index");
    fixture.remove("repository.json");
    const CommandOutput kOutput = run({"check_repository",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::InternalError);
}

TEST(Command, AWrongInvocationExitsTwoAndChecksNothing) {
    EXPECT_EQ(run({}).exitClass, ExitClass::UsageError);
    EXPECT_EQ(run({"check_repository"}).exitClass, ExitClass::UsageError);
    EXPECT_EQ(run({"check_repository", "--root"}).exitClass, ExitClass::UsageError);
    EXPECT_EQ(run({"no_such_operation", "--root", "."}).exitClass, ExitClass::UsageError);
    EXPECT_EQ(run({"check_repository", "--root", ".", "--unknown", "x"}).exitClass, ExitClass::UsageError);
}

TEST(Command, WritesNothingWhenNoReportPathIsGiven) {
    testing::RepositoryFixture fixture("command-no-report");
    const CommandOutput kOutput = run({"check_repository",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::Clean);
    EXPECT_FALSE(std::filesystem::exists(fixture.root() / "out"));
}

TEST(Command, WritesTheDocumentTheCallerAskedForAndNothingElse) {
    testing::RepositoryFixture fixture("command-report");
    const std::filesystem::path kReport = fixture.root() / "out/reports/archcheck/findings.json";
    const CommandOutput kOutput = run({"check_repository",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath(),
                                       "--report",
                                       kReport.string()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::Clean);
    ASSERT_TRUE(std::filesystem::exists(kReport));
    EXPECT_EQ(readAll(kReport), kOutput.standardOutput);
}

TEST(Command, ListRulesSaysHowManySubjectsEachRuleHad) {
    testing::RepositoryFixture fixture("command-list");
    const CommandOutput kOutput = run({"list_rules",
                                       "--root",
                                       fixture.root().string(),
                                       "--corpus",
                                       testing::RepositoryFixture::corpusRelativePath()});
    EXPECT_EQ(kOutput.exitClass, ExitClass::Clean) << kOutput.standardError;
    EXPECT_NE(kOutput.standardOutput.find("policyVersion "), std::string::npos);
    EXPECT_NE(kOutput.standardOutput.find("RA1002 spec.0001 now subjects="), std::string::npos);
    // A rule whose subjects do not exist yet says so rather than staying silent.
    EXPECT_NE(kOutput.standardOutput.find("RA2001 spec.0007 TASK-0011 subjects=0"), std::string::npos);
}

TEST(Command, ExplainRuleAnswersFromTheCorpusAndRefusesAnIdentityItDoesNotCarry) {
    testing::RepositoryFixture fixture("command-explain");
    const CommandOutput kFound = run({"explain_rule",
                                      "--root",
                                      fixture.root().string(),
                                      "--corpus",
                                      testing::RepositoryFixture::corpusRelativePath(),
                                      "--rule",
                                      "RA5001"});
    EXPECT_EQ(kFound.exitClass, ExitClass::Clean);
    EXPECT_NE(kFound.standardOutput.find("authority adr.0008"), std::string::npos);

    const CommandOutput kMissing = run({"explain_rule",
                                        "--root",
                                        fixture.root().string(),
                                        "--corpus",
                                        testing::RepositoryFixture::corpusRelativePath(),
                                        "--rule",
                                        "RA9999"});
    EXPECT_EQ(kMissing.exitClass, ExitClass::UsageError);
}

} // namespace rawframe::tool::archcheck
