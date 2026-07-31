#include "coverage_export.h"
#include "json_reader.h"
#include "verify_fixture.h"

#include <gtest/gtest.h>
#include <string>

namespace rawframe::tool::verify {

namespace {

McdcTestVector vectorOf(std::vector<McdcTestVector::ConditionValue> conditions, bool result, bool executed = true) {
    McdcTestVector vector;
    vector.conditions = std::move(conditions);
    vector.result = result;
    vector.executed = executed;
    return vector;
}

constexpr auto kTrue = McdcTestVector::ConditionValue::True;
constexpr auto kFalse = McdcTestVector::ConditionValue::False;
constexpr auto kAbsent = McdcTestVector::ConditionValue::Absent;

Result<CoverageExport> buildFrom(const testing::RepositoryFixture& fixture, std::string_view document) {
    auto parsed = parseJson(document);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return buildCoverageExport(fixture.root(), *parsed);
}

} // namespace

TEST(CoverageExport, ReadsBranchRegionsAndTheFileSummary) {
    const testing::RepositoryFixture kFixture("export_branches");
    auto coverage = buildFrom(kFixture, kFixture.exportFor("[[12,9,12,14,3,0,0,0,6],[12,18,12,23,1,4,0,0,6]]"));
    ASSERT_TRUE(coverage.has_value()) << coverage.error().message;
    EXPECT_EQ(coverage->producerVersion, "3.1.0");
    ASSERT_EQ(coverage->files.size(), 1U);

    const CoverageFile& kFile = coverage->files.at("tools/subject/src/parser.cpp");
    ASSERT_EQ(kFile.branches.size(), 2U);
    EXPECT_EQ(kFile.branches.at(0).line, 12U);
    EXPECT_EQ(kFile.branches.at(0).column, 9U);
    EXPECT_TRUE(kFile.branches.at(0).trueCovered());
    EXPECT_FALSE(kFile.branches.at(0).falseCovered());
    EXPECT_TRUE(kFile.branches.at(1).trueCovered());
    EXPECT_TRUE(kFile.branches.at(1).falseCovered());
    EXPECT_EQ(kFile.summary.branches.count, 2);
    EXPECT_EQ(kFile.summary.branches.covered, 1);
    EXPECT_EQ(kFile.summary.lines.count, 1);
}

TEST(CoverageExport, DerivesLineCountsFromSegmentsAndKeepsTheHighestPerLine) {
    const testing::RepositoryFixture kFixture("export_segments");
    auto coverage =
        buildFrom(kFixture,
                  kFixture.exportFor("[]",
                                     "[]",
                                     "[[4,1,0,true,true,false],[4,20,7,true,false,false],[6,1,0,true,true,false],"
                                     "[8,1,0,false,true,false]]"));
    ASSERT_TRUE(coverage.has_value()) << coverage.error().message;
    const CoverageFile& kFile = coverage->files.at("tools/subject/src/parser.cpp");
    ASSERT_EQ(kFile.lineCounts.size(), 2U);
    EXPECT_EQ(kFile.lineCounts.at(4), 7);
    EXPECT_EQ(kFile.lineCounts.at(6), 0);
    EXPECT_FALSE(kFile.lineCounts.contains(8));
}

TEST(CoverageExport, DropsFilesThatAreNotMaintainedFirstPartySource) {
    const testing::RepositoryFixture kFixture("export_foreign");
    std::string document = R"({"version":"3.1.0","type":"llvm.coverage.json.export","data":[{"files":[)";
    document += R"({"filename":"/usr/include/c++/v1/vector","branches":[],"mcdc_records":[],"segments":[],)";
    document += R"("summary":{"lines":{"count":1,"covered":1},"branches":{"count":0,"covered":0},)";
    document += R"("regions":{"count":1,"covered":1},"mcdc":{"count":0,"covered":0}}}]}]})";
    auto coverage = buildFrom(kFixture, document);
    ASSERT_TRUE(coverage.has_value()) << coverage.error().message;
    EXPECT_TRUE(coverage->files.empty());
    EXPECT_EQ(coverage->droppedForeignFiles, 1U);
}

TEST(CoverageExport, RejectsADocumentThatIsNotAnLlvmCovExport) {
    const testing::RepositoryFixture kFixture("export_wrong_type");
    auto notAnObject = buildFrom(kFixture, R"([1,2,3])");
    ASSERT_FALSE(notAnObject.has_value());
    EXPECT_EQ(notAnObject.error().code, FailureCode::InvalidJson);

    auto wrongType = buildFrom(kFixture, R"({"type":"something.else","data":[]})");
    ASSERT_FALSE(wrongType.has_value());
    EXPECT_EQ(wrongType.error().code, FailureCode::InvalidJson);

    auto noData = buildFrom(kFixture, R"({"type":"llvm.coverage.json.export"})");
    ASSERT_FALSE(noData.has_value());
    EXPECT_EQ(noData.error().code, FailureCode::InvalidJson);

    auto noFiles = buildFrom(kFixture, R"({"type":"llvm.coverage.json.export","data":[{}]})");
    ASSERT_FALSE(noFiles.has_value());
    EXPECT_EQ(noFiles.error().code, FailureCode::InvalidJson);

    auto noName = buildFrom(kFixture, R"({"type":"llvm.coverage.json.export","data":[{"files":[{}]}]})");
    ASSERT_FALSE(noName.has_value());
    EXPECT_EQ(noName.error().code, FailureCode::InvalidJson);
}

TEST(CoverageExport, RejectsAFileWhoseSummaryIsAbsentOrIncomplete) {
    const testing::RepositoryFixture kFixture("export_bad_summary");
    std::string filename = (kFixture.root() / "tools/subject/src/parser.cpp").generic_string();
    std::string prefix = R"({"type":"llvm.coverage.json.export","data":[{"files":[{"filename":")" + filename + R"(",)";

    auto missing = buildFrom(kFixture, prefix + R"("branches":[]}]}]})");
    ASSERT_FALSE(missing.has_value());
    EXPECT_EQ(missing.error().code, FailureCode::InvalidJson);

    auto partial = buildFrom(kFixture, prefix + R"("summary":{"lines":{"count":1}}}]}]})");
    ASSERT_FALSE(partial.has_value());
    EXPECT_EQ(partial.error().code, FailureCode::InvalidJson);

    auto wrongKind = buildFrom(kFixture, prefix + R"("summary":{"lines":{"count":"one","covered":1}}}]}]})");
    ASSERT_FALSE(wrongKind.has_value());
    EXPECT_EQ(wrongKind.error().code, FailureCode::InvalidJson);
}

TEST(CoverageExport, RejectsAMalformedBranchSegmentOrDecisionRecord) {
    const testing::RepositoryFixture kFixture("export_bad_records");

    auto shortBranch = buildFrom(kFixture, kFixture.exportFor("[[1,2,3]]"));
    ASSERT_FALSE(shortBranch.has_value());
    EXPECT_EQ(shortBranch.error().code, FailureCode::InvalidJson);

    auto branchNotAnArray = buildFrom(kFixture, kFixture.exportFor("7"));
    ASSERT_FALSE(branchNotAnArray.has_value());
    EXPECT_EQ(branchNotAnArray.error().code, FailureCode::InvalidJson);

    auto negativeLine = buildFrom(kFixture, kFixture.exportFor("[[-3,9,12,14,1,0,0,0,6]]"));
    ASSERT_FALSE(negativeLine.has_value());
    EXPECT_EQ(negativeLine.error().code, FailureCode::InvalidJson);

    auto shortSegment = buildFrom(kFixture, kFixture.exportFor("[]", "[]", "[[4,1,0]]"));
    ASSERT_FALSE(shortSegment.has_value());
    EXPECT_EQ(shortSegment.error().code, FailureCode::InvalidJson);

    auto segmentNotAnArray = buildFrom(kFixture, kFixture.exportFor("[]", "[]", "9"));
    ASSERT_FALSE(segmentNotAnArray.has_value());
    EXPECT_EQ(segmentNotAnArray.error().code, FailureCode::InvalidJson);

    auto shortDecision = buildFrom(kFixture, kFixture.exportFor("[]", "[[1,2,3,4]]"));
    ASSERT_FALSE(shortDecision.has_value());
    EXPECT_EQ(shortDecision.error().code, FailureCode::InvalidJson);

    auto decisionNotAnArray = buildFrom(kFixture, kFixture.exportFor("[]", "5"));
    ASSERT_FALSE(decisionNotAnArray.has_value());
    EXPECT_EQ(decisionNotAnArray.error().code, FailureCode::InvalidJson);

    auto noVectorList = buildFrom(kFixture, kFixture.exportFor("[]", "[[2,9,2,23,1,0,0,0,5,3,4]]"));
    ASSERT_FALSE(noVectorList.has_value());
    EXPECT_EQ(noVectorList.error().code, FailureCode::InvalidJson);
}

TEST(CoverageExport, RejectsAMalformedMcdcTestVector) {
    const testing::RepositoryFixture kFixture("export_bad_vectors");
    const std::string kHeader = "[[2,9,2,23,1,0,0,0,5,[false,false],";

    auto notAnObject = buildFrom(kFixture, kFixture.exportFor("[]", kHeader + "[3]]]"));
    ASSERT_FALSE(notAnObject.has_value());
    EXPECT_EQ(notAnObject.error().code, FailureCode::InvalidJson);

    auto incomplete = buildFrom(kFixture, kFixture.exportFor("[]", kHeader + R"([{"conditions":[true,true]}]]])"));
    ASSERT_FALSE(incomplete.has_value());
    EXPECT_EQ(incomplete.error().code, FailureCode::InvalidJson);

    auto wrongWidth = buildFrom(
        kFixture, kFixture.exportFor("[]", kHeader + R"([{"conditions":[true],"executed":true,"result":true}]]])"));
    ASSERT_FALSE(wrongWidth.has_value());
    EXPECT_EQ(wrongWidth.error().code, FailureCode::InvalidJson);

    auto wrongConditionKind = buildFrom(
        kFixture, kFixture.exportFor("[]", kHeader + R"([{"conditions":[1,true],"executed":true,"result":true}]]])"));
    ASSERT_FALSE(wrongConditionKind.has_value());
    EXPECT_EQ(wrongConditionKind.error().code, FailureCode::InvalidJson);
}

TEST(CoverageExport, ReadsADecisionAndItsDontCareConditions) {
    const testing::RepositoryFixture kFixture("export_decision");
    const std::string kRecord = R"([[2,9,2,23,1,2,0,0,5,[true,true],[)"
                                R"({"conditions":[false,null],"executed":true,"result":false},)"
                                R"({"conditions":[true,false],"executed":true,"result":false},)"
                                R"({"conditions":[true,true],"executed":true,"result":true}]]])";
    auto coverage = buildFrom(kFixture, kFixture.exportFor("[]", kRecord));
    ASSERT_TRUE(coverage.has_value()) << coverage.error().message;
    const CoverageFile& kFile = coverage->files.at("tools/subject/src/parser.cpp");
    ASSERT_EQ(kFile.decisions.size(), 1U);
    EXPECT_EQ(kFile.decisions.at(0).line, 2U);
    EXPECT_EQ(kFile.decisions.at(0).conditionCount, 2U);
    ASSERT_EQ(kFile.decisions.at(0).vectors.size(), 3U);
    EXPECT_EQ(kFile.decisions.at(0).vectors.at(0).conditions.at(1), kAbsent);
    // The same corpus llvm-cov reports as fully covered MC/DC, so the two agree
    // on the case that matters rather than only on the shape of the record.
    EXPECT_TRUE(decisionIsIndependentlyCovered(kFile.decisions.at(0)));
}

TEST(CoverageExport, FindsAnIndependencePairOnlyWhenOneExists) {
    McdcDecision covered;
    covered.conditionCount = 2;
    covered.vectors = {
        vectorOf({kFalse, kAbsent}, false), vectorOf({kTrue, kFalse}, false), vectorOf({kTrue, kTrue}, true)};
    EXPECT_TRUE(decisionIsIndependentlyCovered(covered));

    McdcDecision oneVector;
    oneVector.conditionCount = 2;
    oneVector.vectors = {vectorOf({kTrue, kTrue}, true)};
    EXPECT_FALSE(decisionIsIndependentlyCovered(oneVector));

    // The outcome never changes, so nothing can be shown to affect it.
    McdcDecision sameOutcome;
    sameOutcome.conditionCount = 2;
    sameOutcome.vectors = {vectorOf({kTrue, kTrue}, true), vectorOf({kFalse, kTrue}, true)};
    EXPECT_FALSE(decisionIsIndependentlyCovered(sameOutcome));

    // Both conditions move at once, so neither is independently demonstrated.
    McdcDecision bothMove;
    bothMove.conditionCount = 2;
    bothMove.vectors = {vectorOf({kTrue, kTrue}, true), vectorOf({kFalse, kFalse}, false)};
    EXPECT_FALSE(decisionIsIndependentlyCovered(bothMove));

    // A pair exists on paper but one vector never ran.
    McdcDecision notExecuted;
    notExecuted.conditionCount = 1;
    notExecuted.vectors = {vectorOf({kTrue}, true), vectorOf({kFalse}, false, false)};
    EXPECT_FALSE(decisionIsIndependentlyCovered(notExecuted));

    // A condition that is a don't-care in every vector is never demonstrated.
    McdcDecision alwaysAbsent;
    alwaysAbsent.conditionCount = 2;
    alwaysAbsent.vectors = {vectorOf({kTrue, kAbsent}, true), vectorOf({kFalse, kAbsent}, false)};
    EXPECT_FALSE(decisionIsIndependentlyCovered(alwaysAbsent));

    McdcDecision noConditions;
    EXPECT_FALSE(decisionIsIndependentlyCovered(noConditions));
}

TEST(CoverageExport, ReadsAnExportFromDiskAndNamesItOnFailure) {
    const testing::RepositoryFixture kFixture("export_from_disk");
    const auto kPath = kFixture.writeExport("[[12,9,12,14,1,1,0,0,6]]");
    auto coverage = readCoverageExport(kFixture.root(), kPath);
    ASSERT_TRUE(coverage.has_value()) << coverage.error().message;
    EXPECT_EQ(coverage->files.size(), 1U);

    kFixture.write("out/coverage/export.json", R"({"type":"not.an.export","data":[]})");
    auto rejected = readCoverageExport(kFixture.root(), kPath);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, FailureCode::InvalidJson);
    EXPECT_NE(rejected.error().path.find("export.json"), std::string::npos);

    auto absent = readCoverageExport(kFixture.root(), kFixture.root() / "out/coverage/absent.json");
    ASSERT_FALSE(absent.has_value());
    EXPECT_EQ(absent.error().code, FailureCode::MissingInput);
}

} // namespace rawframe::tool::verify
