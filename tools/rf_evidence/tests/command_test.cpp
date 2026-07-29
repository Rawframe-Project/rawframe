#include "command.h"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <sstream>
#include <string_view>
#include <system_error>

namespace rawframe::tool::evidence {

namespace {

// Restores the process working directory so the relative-root probe cannot
// leak state into other tests.
class ScopedWorkingDirectory {
public:
    explicit ScopedWorkingDirectory(const std::filesystem::path& next) : previous_(std::filesystem::current_path()) {
        std::filesystem::current_path(next);
    }
    ~ScopedWorkingDirectory() {
        std::error_code error;
        std::filesystem::current_path(previous_, error);
    }
    ScopedWorkingDirectory(const ScopedWorkingDirectory&) = delete;
    ScopedWorkingDirectory& operator=(const ScopedWorkingDirectory&) = delete;
    ScopedWorkingDirectory(ScopedWorkingDirectory&&) = delete;
    ScopedWorkingDirectory& operator=(ScopedWorkingDirectory&&) = delete;

private:
    std::filesystem::path previous_;
};

} // namespace

TEST(Command, AcceptsRelativeRepositoryRoot) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    const ScopedWorkingDirectory kWorkingDirectory(kRoot);
    constexpr std::array<std::string_view, 4> kArguments{"validate", "repository", "--root", "."};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(runCommand(kArguments, output, errors), 0) << errors.str();
}

// `--format json` means the same thing for every operation. Source ownership is
// the one whose human output is a listing rather than a sentence, and it
// answered JSON with that listing until this was asserted.
TEST(Command, AnswersEveryOperationInTheRequestedFormat) {
    const std::filesystem::path kRoot = RAWFRAME_TEST_REPOSITORY_ROOT;
    const auto kRootText = kRoot.generic_string();
    for (const std::array<std::string_view, 2> kSubject :
         {std::array<std::string_view, 2>{"validate", "repository"},
          std::array<std::string_view, 2>{"graph", "repository"},
          std::array<std::string_view, 2>{"inspect", "source-ownership"},
          std::array<std::string_view, 2>{"review", "licenses"},
          std::array<std::string_view, 2>{"audit", "paths"},
          std::array<std::string_view, 2>{"audit", "shipping-closure"}}) {
        const std::array<std::string_view, 6> kArguments{
            kSubject.front(), kSubject.back(), "--root", kRootText, "--format", "json"};
        std::ostringstream output;
        std::ostringstream errors;
        EXPECT_EQ(runCommand(kArguments, output, errors), 0) << errors.str();
        EXPECT_NE(output.str().find("\"ok\":true"), std::string::npos)
            << kSubject.front() << ' ' << kSubject.back() << ": " << output.str();
    }
}

TEST(Command, RejectsMissingRepositoryRoot) {
    constexpr std::array<std::string_view, 2> kArguments{"validate", "repository"};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(runCommand(kArguments, output, errors), 2);
    EXPECT_NE(errors.str().find("repository root is required"), std::string::npos);
}

} // namespace rawframe::tool::evidence
