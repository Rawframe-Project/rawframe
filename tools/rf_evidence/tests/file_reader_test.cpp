#include "file_reader.h"

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

namespace {

std::filesystem::path writeFixture(std::string_view name, std::string_view bytes) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "file_reader";
    std::filesystem::create_directories(kRoot);
    const auto kPath = kRoot / name;
    std::ofstream output(kPath, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return kPath;
}

} // namespace

TEST(FileReader, AdmitsAFileOfExactlyTheByteLimit) {
    const std::string kBytes(kMaximumMaintainedJsonBytes, 'a');
    const auto kPath = writeFixture("at_limit.txt", kBytes);
    auto result = readBoundedFile(kPath);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->size(), kMaximumMaintainedJsonBytes);
}

TEST(FileReader, RejectsAFileOneByteOverTheLimit) {
    const std::string kBytes(kMaximumMaintainedJsonBytes + 1U, 'a');
    const auto kPath = writeFixture("over_limit.txt", kBytes);
    auto result = readBoundedFile(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::LimitExceeded);
}

// The limit is a parameter rather than a fixed property of the reader, so the
// boundary pair is proven again at a caller-supplied limit. A reader that
// honoured only its default would pass the pair above and fail here.
TEST(FileReader, AppliesTheBoundaryPairToACallerSuppliedLimit) {
    const auto kPath = writeFixture("caller_limit.txt", std::string(16U, 'a'));
    EXPECT_TRUE(readBoundedFile(kPath, 16U).has_value());
    auto result = readBoundedFile(kPath, 15U);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::LimitExceeded);
}

TEST(FileReader, RejectsAMissingFile) {
    const auto kPath = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "file_reader" / "absent.json";
    std::filesystem::remove(kPath);
    auto result = readBoundedFile(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::MissingInput);
}

// A directory is present but is not a maintained file. It must be rejected as
// an inadmissible path rather than as a missing one, and it must fail the same
// way on both host tuples: left to the size probe, Linux errors and Windows
// succeeds and then fails at open, giving one input two typed failures.
TEST(FileReader, RejectsADirectoryAsAnInadmissiblePathRatherThanAMissingOne) {
    const auto kPath = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "file_reader" / "directory_input";
    std::filesystem::create_directories(kPath);
    auto result = readBoundedFile(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidPath);
}

// The two neighbouring rejections must stay distinguishable. A reader that
// collapsed them would still reject both and would hide which one occurred.
TEST(FileReader, SeparatesAMissingPathFromAPresentNonRegularOne) {
    const auto kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "file_reader";
    std::filesystem::create_directories(kRoot / "present_directory");
    const auto kAbsent = kRoot / "absent_neighbour.json";
    std::filesystem::remove(kAbsent);

    auto missing = readBoundedFile(kAbsent);
    ASSERT_FALSE(missing.has_value());
    auto directory = readBoundedFile(kRoot / "present_directory");
    ASSERT_FALSE(directory.has_value());
    EXPECT_NE(missing.error().code, directory.error().code);
}

TEST(FileReader, RejectsInvalidUtf8) {
    const std::string kBytes{"{\"name\":\"\xC3\x28\"}"};
    const auto kPath = writeFixture("invalid_utf8.json", kBytes);
    auto result = readBoundedFile(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidJson);
}

TEST(FileReader, RejectsAnUnpairedSurrogateEncodedAsBytes) {
    const std::string kBytes{"{\"name\":\"\xED\xA0\x80\"}"};
    const auto kPath = writeFixture("surrogate.json", kBytes);
    auto result = readBoundedFile(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidJson);
}

TEST(FileReader, RejectsAUtf8ByteOrderMark) {
    const std::string kBytes{"\xEF\xBB\xBF{}", 5U};
    const auto kPath = writeFixture("bom.json", kBytes);
    auto result = readBoundedFile(kPath);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::InvalidJson);
}

// Rejection must not depend on the mark being the whole file, and a mark that
// merely appears later is ordinary valid text rather than a leading mark.
TEST(FileReader, RejectsALeadingMarkButNotAnInteriorOne) {
    const std::string kLeading{"\xEF\xBB\xBF{\"a\":1}", 10U};
    auto leading = readBoundedFile(writeFixture("bom_leading.json", kLeading));
    ASSERT_FALSE(leading.has_value());
    EXPECT_EQ(leading.error().code, FailureCode::InvalidJson);

    const std::string kInterior{"{\"a\":\"\xEF\xBB\xBF\"}", 11U};
    EXPECT_TRUE(readBoundedFile(writeFixture("bom_interior.json", kInterior)).has_value());
}

TEST(FileReader, ReturnsTheExactBytesOfAnAdmittedFile) {
    const std::string_view kBytes = "{\"name\":\"value\"}";
    const auto kPath = writeFixture("exact.json", kBytes);
    auto result = readBoundedFile(kPath);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(std::string_view(result->data(), result->size()), kBytes);
}

// An empty file carries no mark and no invalid sequence, so the reader admits
// it and the JSON parser is left to reject it. Proving that here keeps the
// division of responsibility explicit rather than incidental.
TEST(FileReader, AdmitsAnEmptyFileAndLeavesRejectionToTheParser) {
    const auto kPath = writeFixture("empty.json", "");
    auto result = readBoundedFile(kPath);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->size(), 0U);
}

} // namespace rawframe::tool::evidence
