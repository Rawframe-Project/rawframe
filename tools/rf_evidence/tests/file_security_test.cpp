#include "file_security.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace rawframe::tool::evidence {

namespace {

// Every case owns a leaf so that a parallel CTest run cannot have two cases
// classifying each other's files. The ordinal is unique without a clock.
std::filesystem::path scratch(std::string_view label) {
    static std::atomic<unsigned long long> leaves{0};
    const std::filesystem::path kRoot = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "file_security" /
                                        (std::string(label) + "." + std::to_string(leaves.fetch_add(1U)));
    std::filesystem::remove_all(kRoot);
    std::filesystem::create_directories(kRoot);
    return kRoot;
}

std::filesystem::path writeFile(const std::filesystem::path& path, std::string_view content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    return path;
}

std::string readAllBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream content;
    content << input.rdbuf();
    return std::move(content).str();
}

// Windows symbolic links need a privilege an ordinary developer session does
// not have; a directory junction needs none. Linux has symbolic links for free.
// A case that cannot construct its subject on a host says so rather than
// reporting a pass it did not earn.
#ifdef _WIN32

// A mount-point reparse point, which is what `mklink /J` writes and what an
// unprivileged Windows process can actually plant. It is constructed here
// rather than shelled out to, because `mklink` is an interpreter builtin and
// this repository's bounded process runner treats every argument as a path,
// which turns `/J` into `\J`.
bool createJunction(const std::filesystem::path& link, const std::filesystem::path& target) {
    std::error_code error;
    std::filesystem::create_directory(link, error);
    if (error) {
        return false;
    }

    const std::wstring kAbsolute = std::filesystem::absolute(target).make_preferred().wstring();
    const std::wstring kSubstitute = L"\\??\\" + kAbsolute;
    const std::size_t kSubstituteBytes = kSubstitute.size() * sizeof(wchar_t);
    const std::size_t kPrintBytes = kAbsolute.size() * sizeof(wchar_t);

    // Header, then the mount-point fields, then both names with a terminator
    // each. The offsets below are measured from the start of the name buffer.
    constexpr std::size_t kHeaderBytes = 8U;
    constexpr std::size_t kFieldBytes = 8U;
    const std::size_t kNameBytes = kSubstituteBytes + sizeof(wchar_t) + kPrintBytes + sizeof(wchar_t);
    std::vector<unsigned char> buffer(kHeaderBytes + kFieldBytes + kNameBytes, 0U);

    const auto kTag = static_cast<std::uint32_t>(IO_REPARSE_TAG_MOUNT_POINT);
    const auto kDataLength = static_cast<std::uint16_t>(kFieldBytes + kNameBytes);
    const std::uint16_t kSubstituteOffset = 0;
    const auto kSubstituteLength = static_cast<std::uint16_t>(kSubstituteBytes);
    const auto kPrintOffset = static_cast<std::uint16_t>(kSubstituteBytes + sizeof(wchar_t));
    const auto kPrintLength = static_cast<std::uint16_t>(kPrintBytes);

    unsigned char* const kBytes = buffer.data();
    std::memcpy(kBytes, &kTag, sizeof(kTag));
    std::memcpy(kBytes + 4, &kDataLength, sizeof(kDataLength));
    std::memcpy(kBytes + 8, &kSubstituteOffset, sizeof(kSubstituteOffset));
    std::memcpy(kBytes + 10, &kSubstituteLength, sizeof(kSubstituteLength));
    std::memcpy(kBytes + 12, &kPrintOffset, sizeof(kPrintOffset));
    std::memcpy(kBytes + 14, &kPrintLength, sizeof(kPrintLength));
    // The two names are copied byte by byte rather than with memcpy: they are
    // wide-character content inside a binary structure and are deliberately not
    // null terminated by the copy, which is what a memcpy of a string looks
    // like to a static analyzer.
    const auto* const kSubstituteBytesBegin = reinterpret_cast<const unsigned char*>(kSubstitute.data());
    const auto* const kPrintBytesBegin = reinterpret_cast<const unsigned char*>(kAbsolute.data());
    std::copy_n(kSubstituteBytesBegin, kSubstituteBytes, kBytes + 16 + kSubstituteOffset);
    std::copy_n(kPrintBytesBegin, kPrintBytes, kBytes + 16 + kPrintOffset);

    const HANDLE kHandle = CreateFileW(link.c_str(),
                                       GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_EXISTING,
                                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                       nullptr);
    if (kHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD returned = 0;
    const BOOL kApplied = DeviceIoControl(
        kHandle, FSCTL_SET_REPARSE_POINT, kBytes, static_cast<DWORD>(buffer.size()), nullptr, 0, &returned, nullptr);
    CloseHandle(kHandle);
    return kApplied != 0;
}

#endif

} // namespace

// Deliberately outside the anonymous namespace: the store suite needs the same
// real reparse point to prove it refuses one as a source, and this Task's
// envelope names exactly two test files, so there is nowhere to put a shared
// header without widening it. blob_store_test.cpp declares this by hand.
std::string createIndirection(const std::filesystem::path& link, const std::filesystem::path& target) {
    std::error_code error;
    std::filesystem::create_directory_symlink(target, link, error);
    if (!error) {
        return {};
    }
#ifdef _WIN32
    // A symbolic link needs a privilege an ordinary developer session does not
    // hold. A junction needs none, so the Windows lane still gets a real
    // reparse point rather than a skipped case.
    std::filesystem::remove_all(link);
    if (createJunction(link, target)) {
        return {};
    }
    return "neither a symbolic link nor a junction could be created";
#else
    return "symbolic link creation failed: " + error.message();
#endif
}

// The anchor. Everything below mutates one property of an ordinary file, so no
// case can pass because classification stopped working altogether.
TEST(FileSecurity, ClassifiesAnOrdinaryFileAsRegular) {
    const auto kRoot = scratch("regular");
    const auto kFile = writeFile(kRoot / "content.bin", "rawframe");
    auto kind = classifyPath(kFile);
    ASSERT_TRUE(kind.has_value()) << (kind ? std::string{} : kind.error().message);
    EXPECT_EQ(*kind, FileKind::Regular);
}

TEST(FileSecurity, ClassifiesADirectoryAsDirectory) {
    const auto kRoot = scratch("directory");
    auto kind = classifyPath(kRoot);
    ASSERT_TRUE(kind.has_value());
    EXPECT_EQ(*kind, FileKind::Directory);
}

TEST(FileSecurity, ClassifiesAnAbsentPathAsMissing) {
    const auto kRoot = scratch("missing");
    auto kind = classifyPath(kRoot / "absent.bin");
    ASSERT_TRUE(kind.has_value());
    EXPECT_EQ(*kind, FileKind::Missing);
}

// The property the store depends on: indirection is seen rather than followed.
TEST(FileSecurity, ClassifiesIndirectionWithoutFollowingIt) {
    const auto kRoot = scratch("indirection");
    const auto kTarget = kRoot / "target";
    std::filesystem::create_directories(kTarget);
    const auto kLink = kRoot / "link";
    if (const std::string kFailure = createIndirection(kLink, kTarget); !kFailure.empty()) {
        GTEST_SKIP() << "this host cannot construct the subject: " << kFailure;
    }
    auto kind = classifyPath(kLink);
    ASSERT_TRUE(kind.has_value());
    EXPECT_EQ(*kind, FileKind::Reparse) << "a followed link would have reported a directory";
}

#ifndef _WIN32
TEST(FileSecurity, ClassifiesAFifoAsSpecial) {
    const auto kRoot = scratch("fifo");
    const auto kFifo = kRoot / "pipe";
    ASSERT_EQ(::mkfifo(kFifo.c_str(), S_IRUSR | S_IWUSR), 0);
    auto kind = classifyPath(kFifo);
    ASSERT_TRUE(kind.has_value());
    EXPECT_EQ(*kind, FileKind::Special);
}
#endif

TEST(FileSecurity, CreatesAndWritesAFileExclusively) {
    const auto kRoot = scratch("create");
    const auto kFile = kRoot / "staged";
    ExclusiveFile file;
    ASSERT_TRUE(file.create(kFile).has_value());
    EXPECT_TRUE(file.isOpen());
    ASSERT_TRUE(file.write("first").has_value());
    ASSERT_TRUE(file.write("-second").has_value());
    ASSERT_TRUE(file.close().has_value());
    EXPECT_FALSE(file.isOpen());
    EXPECT_EQ(readAllBytes(kFile), "first-second");
}

// The guarantee behind the staging retry: a second create never truncates what
// the first one wrote.
TEST(FileSecurity, RefusesToCreateAPathThatAlreadyExists) {
    const auto kRoot = scratch("collision");
    const auto kFile = writeFile(kRoot / "occupied", "existing");
    ExclusiveFile second;
    auto created = second.create(kFile);
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error().code, FailureCode::OwnershipCollision);
    EXPECT_EQ(readAllBytes(kFile), "existing");
}

TEST(FileSecurity, WritesEveryByteIncludingControlAndHighBytes) {
    const auto kRoot = scratch("bytes");
    const auto kFile = kRoot / "exact";
    const std::string kContent{"a\r\nb\0c\x7f\xc3\xa9", 9U};
    ExclusiveFile file;
    ASSERT_TRUE(file.create(kFile).has_value());
    ASSERT_TRUE(file.write(kContent).has_value());
    ASSERT_TRUE(file.close().has_value());
    EXPECT_EQ(readAllBytes(kFile), kContent);
}

TEST(FileSecurity, PublishesOntoAFreePath) {
    const auto kRoot = scratch("publish");
    const auto kStaged = writeFile(kRoot / "staged.tmp", "content");
    const auto kDestination = kRoot / "destination";
    ASSERT_TRUE(publishWithoutReplacement(kStaged, kDestination).has_value());
    EXPECT_TRUE(std::filesystem::exists(kDestination));
    EXPECT_FALSE(std::filesystem::exists(kStaged));
    EXPECT_EQ(readAllBytes(kDestination), "content");
}

// The whole reason this function exists rather than std::filesystem::rename,
// which replaces the destination without saying so.
TEST(FileSecurity, RefusesToPublishOntoAnOccupiedPath) {
    const auto kRoot = scratch("occupied_publish");
    const auto kStaged = writeFile(kRoot / "staged.tmp", "new");
    const auto kDestination = writeFile(kRoot / "destination", "original");
    auto published = publishWithoutReplacement(kStaged, kDestination);
    ASSERT_FALSE(published.has_value());
    EXPECT_EQ(published.error().code, FailureCode::OwnershipCollision);
    EXPECT_EQ(readAllBytes(kDestination), "original") << "the destination must be untouched";
    EXPECT_TRUE(std::filesystem::exists(kStaged)) << "a refused publication keeps the staged file for its caller";
}

} // namespace rawframe::tool::evidence
