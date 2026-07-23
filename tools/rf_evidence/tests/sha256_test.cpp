#include "sha256.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace rawframe::tool::evidence {

TEST(Sha256, HashesKnownVector) {
    const std::filesystem::path kOutputRoot = RAWFRAME_TEST_OUTPUT_ROOT;
    std::error_code error;
    std::filesystem::create_directories(kOutputRoot, error);
    ASSERT_FALSE(error);
    const auto kPath = kOutputRoot / "sha256_abc.txt";
    {
        std::ofstream output(kPath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(output);
        output << "abc";
    }

    auto result = sha256File(kPath);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(*result, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

} // namespace rawframe::tool::evidence
