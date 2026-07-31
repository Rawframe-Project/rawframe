#include "repository_fixture.h"
#include "repository_scan.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace rawframe::tool::archcheck {

TEST(RepositoryScan, OrdersTheTreeIndependentlyOfTheOrderItWasCreatedIn) {
    // The same tree, built twice, with the entries created in opposite orders.
    // A scan that leaked filesystem order would differ here and nowhere else,
    // which is why this is the case rather than a repeated scan of one tree.
    testing::RepositoryFixture ascending("scan-ascending");
    testing::RepositoryFixture descending("scan-descending");
    const std::vector<std::string> kNames{"a/one.txt", "b/two.txt", "c/three.txt", "d/four.txt"};
    for (const auto& name : kNames) {
        ascending.write(name, "x\n");
    }
    for (auto entry = kNames.rbegin(); entry != kNames.rend(); ++entry) {
        descending.write(*entry, "x\n");
    }

    auto first = scanRepository(ascending.root());
    auto second = scanRepository(descending.root());
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    std::vector<std::string> firstPaths;
    std::vector<std::string> secondPaths;
    for (const auto& file : first->files) {
        firstPaths.push_back(file.path);
    }
    for (const auto& file : second->files) {
        secondPaths.push_back(file.path);
    }
    EXPECT_EQ(firstPaths, secondPaths);
    EXPECT_EQ(first->directories, second->directories);
}

TEST(RepositoryScan, DoesNotWalkTheGeneratedRootOrVersionControlState) {
    testing::RepositoryFixture fixture("scan-skips");
    fixture.write("out/reports/archcheck/findings.json", "{}\n");
    fixture.write(".git/config", "[core]\n");
    fixture.write("kept.txt", "x\n");

    auto scan = scanRepository(fixture.root());
    ASSERT_TRUE(scan.has_value());
    EXPECT_TRUE(scan->hasFile("kept.txt"));
    EXPECT_FALSE(scan->hasFile("out/reports/archcheck/findings.json"));
    EXPECT_FALSE(scan->hasFile(".git/config"));
}

TEST(RepositoryScan, ReportsAnAbsentRootRatherThanAnEmptyTree) {
    auto scan = scanRepository(testing::outputRoot() / "no-such-repository");
    ASSERT_FALSE(scan.has_value());
    EXPECT_EQ(scan.error().code, FailureCode::MissingInput);
}

TEST(RepositoryScan, ClassifiesBuildFilesAndFirstPartySourceByPathRatherThanContent) {
    EXPECT_TRUE(isBuildFile("CMakeLists.txt"));
    EXPECT_TRUE(isBuildFile("cmake/rawframe_compiler_policy.cmake"));
    EXPECT_FALSE(isBuildFile("tools/rf_archcheck/src/engine.cpp"));

    EXPECT_TRUE(isFirstPartySource("tools/rf_archcheck/src/engine.cpp"));
    EXPECT_TRUE(isFirstPartySource("source/base/include/rawframe/base/identity.h"));
    EXPECT_FALSE(isFirstPartySource("third_party/vcpkg/toolchains/linux-x86_64.cmake"));
    EXPECT_FALSE(isFirstPartySource("tools/rf_archcheck/tool.json"));
}

TEST(RepositoryScan, ReadsTheExtensionFromTheNameAndNotFromTheDirectory) {
    EXPECT_EQ(fileExtension("a.b/c.cpp"), ".cpp");
    EXPECT_EQ(fileExtension("a.b/c"), "");
    EXPECT_EQ(fileExtension(".gitignore"), "");
}

} // namespace rawframe::tool::archcheck
