#include "diff_reader.h"
#include "verify_fixture.h"

#include <gtest/gtest.h>
#include <string>

namespace rawframe::tool::verify {

TEST(DiffReader, CollectsAddedLinesAndCountsContextButNotRemovals) {
    const std::string kDiff = "diff --git a/tools/subject/src/parser.cpp b/tools/subject/src/parser.cpp\n"
                              "index 1111111..2222222 100644\n"
                              "--- a/tools/subject/src/parser.cpp\n"
                              "+++ b/tools/subject/src/parser.cpp\n"
                              "@@ -10,4 +10,5 @@ int parse()\n"
                              " context\n"
                              "-removed\n"
                              "+added eleven\n"
                              "+added twelve\n"
                              " context\n";
    auto changed = parseUnifiedDiff(kDiff);
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    ASSERT_EQ(changed->files.size(), 1U);
    const auto& kLines = changed->files.at("tools/subject/src/parser.cpp");
    EXPECT_EQ(kLines, (std::set<std::uint32_t>{11, 12}));
}

TEST(DiffReader, ReadsAHunkHeaderWithNoExplicitCount) {
    auto changed = parseUnifiedDiff("+++ b/a/src/x.cpp\n@@ -1 +7 @@\n+one\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_EQ(changed->files.at("a/src/x.cpp"), (std::set<std::uint32_t>{7}));
}

TEST(DiffReader, IgnoresADeletedFileAndItsHunks) {
    auto changed = parseUnifiedDiff("--- a/gone.cpp\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-one\n-two\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_TRUE(changed->empty());
}

TEST(DiffReader, AcceptsAHeaderWithoutTheUsualPrefixOrWithATimestamp) {
    auto changed = parseUnifiedDiff("+++ tools/subject/src/parser.cpp\t2026-07-31\n@@ -1 +3 @@\n+one\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_EQ(changed->files.at("tools/subject/src/parser.cpp"), (std::set<std::uint32_t>{3}));
}

TEST(DiffReader, NormalizesAWindowsSeparatorInAHeader) {
    auto changed = parseUnifiedDiff("+++ b/tools\\subject\\src\\parser.cpp\n@@ -1 +1 @@\n+one\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_TRUE(changed->files.contains("tools/subject/src/parser.cpp"));
}

TEST(DiffReader, IgnoresTheNoNewlineMarkerWithoutAdvancingTheLine) {
    auto changed = parseUnifiedDiff("+++ b/x/src/y.cpp\n@@ -1 +1,2 @@\n+one\n\\ No newline at end of file\n+two\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_EQ(changed->files.at("x/src/y.cpp"), (std::set<std::uint32_t>{1, 2}));
}

TEST(DiffReader, StopsReadingAHunkAtUnrelatedTrailingText) {
    auto changed = parseUnifiedDiff("+++ b/x/src/y.cpp\n@@ -1 +1 @@\n+one\nunrelated trailing text\n+not a line\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_EQ(changed->files.at("x/src/y.cpp"), (std::set<std::uint32_t>{1}));
}

TEST(DiffReader, IgnoresHunkContentBeforeAnyFileHeader) {
    auto changed = parseUnifiedDiff("@@ -1 +1 @@\n+orphan\n");
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_TRUE(changed->empty());
}

TEST(DiffReader, RejectsAHunkHeaderThatIsNotInUnifiedForm) {
    auto missingPlus = parseUnifiedDiff("+++ b/x/src/y.cpp\n@@ -1,2 @@\n+one\n");
    ASSERT_FALSE(missingPlus.has_value());
    EXPECT_EQ(missingPlus.error().code, FailureCode::MalformedDiff);

    auto unterminated = parseUnifiedDiff("+++ b/x/src/y.cpp\n@@ -1,2 +3,4\n+one\n");
    ASSERT_FALSE(unterminated.has_value());
    EXPECT_EQ(unterminated.error().code, FailureCode::MalformedDiff);
}

TEST(DiffReader, RejectsAHunkHeaderWhoseLineNumberIsNotANumber) {
    auto changed = parseUnifiedDiff("+++ b/x/src/y.cpp\n@@ -1,2 +xy,4 @@\n+one\n");
    ASSERT_FALSE(changed.has_value());
    EXPECT_EQ(changed.error().code, FailureCode::MalformedDiff);
}

TEST(DiffReader, RejectsADiffFileThatIsNotThere) {
    auto changed = readUnifiedDiff(testing::outputRoot() / "absent" / "nothing.diff");
    ASSERT_FALSE(changed.has_value());
    EXPECT_EQ(changed.error().code, FailureCode::MissingInput);
}

TEST(DiffReader, ReadsADiffFromDiskAndNamesItOnFailure) {
    const testing::RepositoryFixture kFixture("diff_from_disk");
    const auto kGood = kFixture.writeDiff(testing::diffAddingSubjectLines(4, 2));
    auto changed = readUnifiedDiff(kGood);
    ASSERT_TRUE(changed.has_value()) << changed.error().message;
    EXPECT_EQ(changed->files.at("tools/subject/src/parser.cpp"), (std::set<std::uint32_t>{4, 5}));

    const auto kBad = kFixture.writeDiff("+++ b/x/src/y.cpp\n@@ nonsense @@\n+one\n");
    auto rejected = readUnifiedDiff(kBad);
    ASSERT_FALSE(rejected.has_value());
    EXPECT_EQ(rejected.error().code, FailureCode::MalformedDiff);
    EXPECT_NE(rejected.error().path.find("changed.diff"), std::string::npos);
}

} // namespace rawframe::tool::verify
