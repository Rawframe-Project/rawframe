#include "repository_validator.h"

#include <filesystem>
#include <gtest/gtest.h>

namespace rawframe::tool::evidence {

TEST(RepositoryValidator, AcceptsTaskOneRepository) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    auto result = validateRepository(kRoot);
    ASSERT_TRUE(result.has_value()) << result.error().path << ": " << result.error().message;
    ASSERT_EQ(result->tools.size(), 1U);
    EXPECT_EQ(result->tools.front().id, "rawframe.tool.evidence");
    EXPECT_EQ(result->tools.front().cmakeTarget, "rawframe_tool_rf_evidence");
}

} // namespace rawframe::tool::evidence
