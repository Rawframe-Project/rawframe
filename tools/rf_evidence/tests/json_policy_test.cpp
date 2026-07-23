#include "json_policy.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

std::filesystem::path writeFixture(std::string_view name, std::string_view bytes) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "json_policy";
    std::filesystem::create_directories(kRoot);
    const auto kPath = kRoot / name;
    std::ofstream output(kPath, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return kPath;
}

} // namespace

TEST(JsonPolicy, RejectsDuplicateDecodedMembers) {
    const auto kPath = writeFixture("duplicate.json", R"({"name":1,"\u006eame":2})");
    auto result = validateJsonAdmission(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidJson);
}

TEST(JsonPolicy, RejectsUtf8Bom) {
    const std::string kBytes{"\xEF\xBB\xBF{}", 5U};
    const auto kPath = writeFixture("bom.json", kBytes);
    auto result = validateJsonAdmission(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidJson);
}

TEST(JsonPolicy, AcceptsUniqueNestedMembers) {
    const auto kPath = writeFixture("valid.json", R"({"outer":{"name":1},"items":[{"name":2}]})");
    EXPECT_TRUE(validateJsonAdmission(kPath).has_value());
}

} // namespace rawframe::tool::evidence
