#include "path_policy.h"

#include <filesystem>
#include <gtest/gtest.h>

namespace rawframe::tool::evidence {

TEST(PathPolicy, AcceptsMaintainedRelativePath) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveRepositoryPath(kRoot, "tools/rf_evidence/tool.json");
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->filename(), "tool.json");
}

TEST(PathPolicy, RejectsParentTraversal) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveRepositoryPath(kRoot, "tools/../repository.json");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

TEST(PathPolicy, RejectsWindowsSeparator) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = resolveRepositoryPath(kRoot, "tools\\rf_evidence\\tool.json");
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

} // namespace rawframe::tool::evidence
