#include "repository_paths.h"
#include "verify_fixture.h"

#include <gtest/gtest.h>
#include <string>

namespace rawframe::tool::verify {

TEST(RepositoryPaths, NormalizesWindowsSeparators) {
    EXPECT_EQ(normalizeSeparators(R"(tools\rf_verify\src\floors.cpp)"), "tools/rf_verify/src/floors.cpp");
    EXPECT_EQ(normalizeSeparators("tools/rf_verify/src/floors.cpp"), "tools/rf_verify/src/floors.cpp");
}

TEST(RepositoryPaths, ResolvesARootThatCarriesTheRepositoryIndex) {
    const testing::RepositoryFixture kFixture("paths_root");
    auto resolved = resolveRepositoryRoot(kFixture.root());
    ASSERT_TRUE(resolved.has_value()) << resolved.error().message;
}

TEST(RepositoryPaths, RejectsARootThatIsNotThisRepository) {
    const testing::RepositoryFixture kFixture("paths_not_a_repository");
    kFixture.remove("repository.json");
    auto resolved = resolveRepositoryRoot(kFixture.root());
    ASSERT_FALSE(resolved.has_value());
    EXPECT_EQ(resolved.error().code, FailureCode::MissingInput);
}

TEST(RepositoryPaths, ExpressesAnAbsolutePathRelativeToTheRoot) {
    const testing::RepositoryFixture kFixture("paths_relative");
    auto relative = repositoryRelative(kFixture.root(), (kFixture.root() / "tools/subject/src/parser.cpp").string());
    ASSERT_TRUE(relative.has_value()) << relative.error().message;
    EXPECT_EQ(*relative, "tools/subject/src/parser.cpp");
}

TEST(RepositoryPaths, ExpressesARelativePathAsGiven) {
    const testing::RepositoryFixture kFixture("paths_already_relative");
    auto relative = repositoryRelative(kFixture.root(), "tools/subject/src/parser.cpp");
    ASSERT_TRUE(relative.has_value()) << relative.error().message;
    EXPECT_EQ(*relative, "tools/subject/src/parser.cpp");
}

TEST(RepositoryPaths, RejectsAPathOutsideTheRepository) {
    const testing::RepositoryFixture kFixture("paths_outside");
    auto relative = repositoryRelative(kFixture.root(), (testing::outputRoot() / "elsewhere.cpp").string());
    ASSERT_FALSE(relative.has_value());
    EXPECT_EQ(relative.error().code, FailureCode::InvalidPath);
}

TEST(RepositoryPaths, AdmitsExactlyTheMaintainedFirstPartySourceUnits) {
    EXPECT_TRUE(isMaintainedSourceUnit("tools/rf_verify/src/floors.cpp"));
    EXPECT_TRUE(isMaintainedSourceUnit("tools/rf_verify/src/floors.h"));
    EXPECT_TRUE(isMaintainedSourceUnit("source/base/include/rawframe/base/bytes.h"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/tests/floors_test.cpp"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/src/notes.md"));
    EXPECT_FALSE(isMaintainedSourceUnit("third_party/vendored/src/thing.cpp"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/tool.json"));
    EXPECT_FALSE(isMaintainedSourceUnit("tools/rf_verify/CMakeLists.txt"));
}

TEST(RepositoryPaths, AcceptsAReportDestinationInsideTheDeclaredWriteRoot) {
    const testing::RepositoryFixture kFixture("paths_report_inside");
    auto status = ensureWithinReportRoot(kFixture.root(), kFixture.root() / "out/reports/verify/floors.json");
    ASSERT_TRUE(status.has_value()) << status.error().message;
}

TEST(RepositoryPaths, RejectsAReportDestinationOutsideTheDeclaredWriteRoot) {
    const testing::RepositoryFixture kFixture("paths_report_outside");
    for (const std::string_view kDestination :
         {"out/reports/archcheck/floors.json", "tools/rf_verify/floors.json", "out/reports/verify/../escape.json"}) {
        auto status = ensureWithinReportRoot(kFixture.root(), kFixture.root() / kDestination);
        ASSERT_FALSE(status.has_value()) << kDestination;
        EXPECT_EQ(status.error().code, FailureCode::InvalidPath);
    }
}

TEST(RepositoryPaths, TreatsARelativeReportDestinationAsRootRelative) {
    const testing::RepositoryFixture kFixture("paths_report_relative");
    auto inside = ensureWithinReportRoot(kFixture.root(), "out/reports/verify/floors.json");
    ASSERT_TRUE(inside.has_value()) << inside.error().message;
    auto outside = ensureWithinReportRoot(kFixture.root(), "floors.json");
    ASSERT_FALSE(outside.has_value());
}

} // namespace rawframe::tool::verify
