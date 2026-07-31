#include "coverage_export.h"
#include "json_reader.h"
#include "verify_fixture.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::verify {

namespace {

// Every case here is one malformed `llvm-cov export` document. STD-0007 requires
// a named test for each rejection a verification tool performs, and the reason
// is exactly this file: an export reader that fell through to a default on
// unexpected input would report a repository that met every floor.
std::string documentNaming(std::string_view fileBody) {
    std::string filename = (testing::repositoryRoot() / "tools/subject/src/parser.cpp").generic_string();
    std::string escaped;
    for (const char kCharacter : filename) {
        if (kCharacter == '\\') {
            escaped += "\\\\";
            continue;
        }
        escaped += kCharacter;
    }
    std::string document = R"({"version":"3.1.0","type":"llvm.coverage.json.export","data":[{"files":[{)";
    document += "\"filename\":\"" + escaped + "\"";
    document += fileBody;
    document += "}]}]}";
    return document;
}

constexpr std::string_view kValidSummary =
    R"(,"summary":{"lines":{"count":1,"covered":1},"branches":{"count":2,"covered":1},)"
    R"("regions":{"count":1,"covered":1},"mcdc":{"count":0,"covered":0}})";

Failure buildFailure(std::string_view document) {
    auto parsed = parseJson(document);
    EXPECT_TRUE(parsed.has_value()) << "the fixture itself is not JSON";
    if (!parsed) {
        return Failure{FailureCode::InvalidJson, {}, "unparsable fixture"};
    }
    auto built = buildCoverageExport(testing::repositoryRoot(), *parsed);
    EXPECT_FALSE(built.has_value()) << "the reader accepted a malformed export";
    if (built) {
        return Failure{FailureCode::InvalidJson, {}, "accepted"};
    }
    return built.error();
}

Result<CoverageExport> build(std::string_view document) {
    auto parsed = parseJson(document);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return buildCoverageExport(testing::repositoryRoot(), *parsed);
}

} // namespace

TEST(CoverageExportRejections, RefusesADocumentThatIsNotAnObject) {
    RecordProperty("requirement", "STD-0007:llvm-cov-export-is-the-artifact-of-record");
    EXPECT_EQ(buildFailure("[]").code, FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesADocumentThatDoesNotClaimToBeAnExport) {
    RecordProperty("requirement", "STD-0007:llvm-cov-export-is-the-artifact-of-record");
    EXPECT_EQ(buildFailure(R"({"data":[]})").code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(R"({"type":7,"data":[]})").code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.summary","data":[]})").code, FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesADocumentWithNoDataArray) {
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.export"})").code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.export","data":{}})").code, FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesADataEntryWithNoFileList) {
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.export","data":[{}]})").code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.export","data":[{"files":7}]})").code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesACoveredFileWithNoFilename) {
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.export","data":[{"files":[{}]}]})").code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(R"({"type":"llvm.coverage.json.export","data":[{"files":[{"filename":7}]}]})").code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, DropsAFileThatIsNotAMaintainedUnitOfThisRepository) {
    auto built = build(R"({"type":"llvm.coverage.json.export","data":[{"files":[{"filename":"/usr/include/x.h"}]}]})");
    ASSERT_TRUE(built.has_value()) << built.error().message;
    EXPECT_EQ(built->droppedForeignFiles, 1U);
    EXPECT_TRUE(built->files.empty());
}

TEST(CoverageExportRejections, RefusesAFileWithNoSummary) {
    EXPECT_EQ(buildFailure(documentNaming("")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":7)")).code, FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesASummarySectionThatIsAbsentOrNotAnObject) {
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{})")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{"lines":7})")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{"lines":{"count":1,"covered":1}})")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesAnIncompleteOrNonNumericCountPair) {
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{"lines":{"count":1}})")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{"lines":{"covered":1}})")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{"lines":{"count":"x","covered":1}})")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(R"(,"summary":{"lines":{"count":1,"covered":"x"}})")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, TreatsAnAbsentMcdcSummaryAsALaneThatDidNotAskForIt) {
    std::string body = R"(,"summary":{"lines":{"count":1,"covered":1},"branches":{"count":2,"covered":1},)";
    body += R"("regions":{"count":1,"covered":1}})";
    auto built = build(documentNaming(body));
    ASSERT_TRUE(built.has_value()) << built.error().message;
    ASSERT_EQ(built->files.size(), 1U);
    EXPECT_EQ(built->files.begin()->second.summary.mcdc.count, 0);
}

TEST(CoverageExportRejections, RefusesABranchListThatIsNotAnArrayOfNineFieldRecords) {
    EXPECT_EQ(buildFailure(documentNaming(std::string(kValidSummary) + R"(,"branches":7)")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(std::string(kValidSummary) + R"(,"branches":[7])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(std::string(kValidSummary) + R"(,"branches":[[1,2,3]])")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesABranchRegionWithAFieldThatIsNotAnInteger) {
    const std::string kSummary(kValidSummary);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"branches":[["x",1,1,5,1,1,0,0,6]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"branches":[[1,"x",1,5,1,1,0,0,6]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"branches":[[1,1,1,5,"x",1,0,0,6]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"branches":[[1,1,1,5,1,"x",0,0,6]])")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesALineNumberOutsideTheRepresentableRange) {
    const std::string kSummary(kValidSummary);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"branches":[[5000000000,1,1,5,1,1,0,0,6]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"branches":[[-1,1,1,5,1,1,0,0,6]])")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesAnMcdcRecordListThatIsMalformed) {
    const std::string kSummary(kValidSummary);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":7)")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":[7])")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":[[1,2,3]])")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":[[1,1,1,9,0,0,0,0,0,7,[]]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":[[1,1,1,9,0,0,0,0,0,[],7]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":[["x",1,1,9,0,0,0,0,0,[],[]]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"mcdc_records":[[1,"x",1,9,0,0,0,0,0,[],[]]])")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, RefusesAnMcdcTestVectorThatIsMalformed) {
    const std::string kSummary(kValidSummary);
    const std::string kHead = kSummary + R"(,"mcdc_records":[[1,1,1,9,0,0,0,0,0,[false,false],[)";
    EXPECT_EQ(buildFailure(documentNaming(kHead + R"(7]]])")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kHead + R"({"executed":true,"result":true}]]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kHead + R"({"conditions":[true],"executed":7,"result":true}]]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kHead + R"({"conditions":[true],"executed":true,"result":true}]]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kHead + R"({"conditions":[true,7],"executed":true,"result":true}]]])")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, ReadsADecisionWhoseConditionsIncludeADontCare) {
    const std::string kSummary(kValidSummary);
    std::string body = kSummary + R"(,"mcdc_records":[[9,1,9,20,0,0,0,0,0,[false,false],[)";
    body += R"({"conditions":[true,null],"executed":true,"result":true},)";
    body += R"({"conditions":[false,false],"executed":true,"result":false}]]])";
    auto built = build(documentNaming(body));
    ASSERT_TRUE(built.has_value()) << built.error().message;
    ASSERT_EQ(built->files.size(), 1U);
    const auto& kDecisions = built->files.begin()->second.decisions;
    ASSERT_EQ(kDecisions.size(), 1U);
    EXPECT_EQ(kDecisions.front().line, 9U);
    EXPECT_EQ(kDecisions.front().conditionCount, 2U);
    // The first condition has an independence pair and the second does not, so
    // the decision as a whole is not covered.
    EXPECT_FALSE(decisionIsIndependentlyCovered(kDecisions.front()));
}

TEST(CoverageExportRejections, RefusesASegmentListThatIsMalformed) {
    const std::string kSummary(kValidSummary);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"segments":7)")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"segments":[7])")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"segments":[[1,2,3]])")).code, FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"segments":[["x",1,0,true,true,false]])")).code,
              FailureCode::InvalidJson);
    EXPECT_EQ(buildFailure(documentNaming(kSummary + R"(,"segments":[[1,1,"x",true,true,false]])")).code,
              FailureCode::InvalidJson);
}

TEST(CoverageExportRejections, KeepsTheHighestCountAmongSegmentsSharingALine) {
    const std::string kSummary(kValidSummary);
    std::string body = kSummary + R"(,"segments":[[4,1,0,true,true,false],[4,9,7,true,false,false],)";
    body += R"([5,1,0,false,true,false]])";
    auto built = build(documentNaming(body));
    ASSERT_TRUE(built.has_value()) << built.error().message;
    ASSERT_EQ(built->files.size(), 1U);
    const auto& kCounts = built->files.begin()->second.lineCounts;
    ASSERT_EQ(kCounts.size(), 1U) << "a segment carrying no count is not a line observation";
    EXPECT_EQ(kCounts.at(4), 7);
}

TEST(CoverageExportRejections, NamesTheExportFileWhenTheRejectionItselfNamesNoPath) {
    const testing::RepositoryFixture kFixture("export_failure_path");
    kFixture.write("out/coverage/export.json", R"({"type":"not.an.export"})");
    auto read = readCoverageExport(kFixture.root(), kFixture.root() / "out/coverage/export.json");
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::InvalidJson);
    EXPECT_NE(read.error().path.find("export.json"), std::string::npos);
}

TEST(CoverageExportRejections, KeepsTheRejectionPathWhenTheReaderAlreadyNamedTheUnit) {
    const testing::RepositoryFixture kFixture("export_failure_unit_path");
    kFixture.write("out/coverage/export.json", kFixture.exportFor("7"));
    auto read = readCoverageExport(kFixture.root(), kFixture.root() / "out/coverage/export.json");
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().path, "tools/subject/src/parser.cpp");
}

TEST(CoverageExportRejections, ReadsSeveralExportsAsOneMeasurementWhenTheyNameDifferentUnits) {
    // The lane produces one export per entry point, because a profile merged
    // across programs cannot hold more than one `main`. Reading them together
    // has to give the same answer as reading one export that named both units.
    const testing::RepositoryFixture kFixture("export_several");
    kFixture.write("tools/subject/src/second.cpp", "int second(int value) { return value; }\n");
    kFixture.write("out/coverage/first.json", kFixture.exportFor(R"([[4,1,4,9,1,0,0,0,0]])"));

    std::string second = kFixture.exportFor(R"([[9,1,9,9,1,1,0,0,0]])");
    const std::string kFrom = (kFixture.root() / "tools/subject/src/parser.cpp").generic_string();
    const std::string kTo = (kFixture.root() / "tools/subject/src/second.cpp").generic_string();
    second.replace(second.find(kFrom), kFrom.size(), kTo);
    kFixture.write("out/coverage/second.json", second);

    const std::vector<std::filesystem::path> kExports{kFixture.root() / "out/coverage/first.json",
                                                      kFixture.root() / "out/coverage/second.json"};
    auto read = readCoverageExports(kFixture.root(), kExports);
    ASSERT_TRUE(read.has_value()) << read.error().message;
    EXPECT_EQ(read->files.size(), 2U);
    EXPECT_TRUE(read->files.contains("tools/subject/src/parser.cpp"));
    EXPECT_TRUE(read->files.contains("tools/subject/src/second.cpp"));
    EXPECT_EQ(read->producerVersion, "3.1.0");
}

TEST(CoverageExportRejections, RefusesTwoExportsThatMeasureTheSameUnit) {
    RecordProperty("requirement", "STD-0007:every-rejection-rule-has-a-rejection-test");
    // Two measurements of one file are two numbers, and there is no honest way to
    // pick between them here: keeping the later one would publish a figure the
    // earlier run contradicts, and neither figure would be the file's coverage.
    const testing::RepositoryFixture kFixture("export_same_unit_twice");
    kFixture.write("out/coverage/first.json", kFixture.exportFor(R"([[4,1,4,9,1,0,0,0,0]])"));
    kFixture.write("out/coverage/second.json", kFixture.exportFor(R"([[4,1,4,9,0,1,0,0,0]])"));

    const std::vector<std::filesystem::path> kExports{kFixture.root() / "out/coverage/first.json",
                                                      kFixture.root() / "out/coverage/second.json"};
    auto read = readCoverageExports(kFixture.root(), kExports);
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::InvalidJson);
    EXPECT_EQ(read.error().path, "tools/subject/src/parser.cpp");
}

TEST(CoverageExportRejections, RefusesAnExportFileThatIsNotThere) {
    const testing::RepositoryFixture kFixture("export_absent");
    auto read = readCoverageExport(kFixture.root(), kFixture.root() / "out/coverage/absent.json");
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error().code, FailureCode::MissingInput);
}

} // namespace rawframe::tool::verify
