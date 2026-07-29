#include "process_runner.h"

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace rawframe::tool::evidence {

namespace {

// The pinned CMake is the only interpreter this Task admits, and it is already
// required for every build, so it is the controllable child here. Nothing is
// acquired, and no shell is involved.
std::filesystem::path pinnedCMake() {
    return std::filesystem::path{RAWFRAME_TEST_CMAKE_COMMAND};
}

std::filesystem::path caseDirectory(std::string_view name) {
    const auto kPath = std::filesystem::path(RAWFRAME_TEST_OUTPUT_ROOT) / "process_runner" / name;
    std::filesystem::remove_all(kPath);
    std::filesystem::create_directories(kPath);
    return kPath;
}

ProcessRequest requestFor(std::string_view name, std::vector<std::string> arguments) {
    const auto kDirectory = caseDirectory(name);
    return ProcessRequest{
        .executable = pinnedCMake(),
        .arguments = std::move(arguments),
        .workingDirectory = kDirectory,
        .captureDirectory = kDirectory / "capture",
    };
}

} // namespace

TEST(ProcessRunner, CapturesStandardOutputAndAZeroExitCode) {
    auto result = runBoundedProcess(requestFor("echo", {"-E", "echo", "rawframe"}));
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->exitCode, 0);
    EXPECT_NE(result->standardOutput.find("rawframe"), std::string::npos);
    EXPECT_TRUE(result->standardError.empty());
}

// A non-zero exit is an observation, not a failure of the runner. Collapsing
// the two would make every failing child indistinguishable from a broken run.
TEST(ProcessRunner, ReportsANonZeroExitCodeAsAValueRatherThanAFailure) {
    auto result = runBoundedProcess(requestFor("false", {"-E", "false"}));
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_NE(result->exitCode, 0);
}

TEST(ProcessRunner, KeepsStandardOutputAndStandardErrorSeparate) {
    auto result = runBoundedProcess(requestFor("streams", {"-E", "echo", "only-out"}));
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_NE(result->standardOutput.find("only-out"), std::string::npos);
    EXPECT_EQ(result->standardError.find("only-out"), std::string::npos);
}

TEST(ProcessRunner, RejectsARelativeExecutablePath) {
    auto request = requestFor("relative", {"-E", "true"});
    request.executable = std::filesystem::path{"cmake"};
    auto result = runBoundedProcess(request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::MissingInput);
}

TEST(ProcessRunner, RejectsAMissingExecutable) {
    auto request = requestFor("absent", {"-E", "true"});
    request.executable = pinnedCMake().parent_path() / "no_such_executable_here";
    auto result = runBoundedProcess(request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::MissingInput);
}

TEST(ProcessRunner, RejectsADirectoryAsAnExecutable) {
    auto request = requestFor("directory", {"-E", "true"});
    request.executable = pinnedCMake().parent_path();
    auto result = runBoundedProcess(request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::MissingInput);
}

// Wall time is a declared limit, so it is proven rather than assumed. The
// child sleeps well past a deliberately short deadline.
TEST(ProcessRunner, TerminatesAChildThatExceedsItsWallClockDeadline) {
    auto request = requestFor("timeout", {"-E", "sleep", "10"});
    request.timeout = std::chrono::milliseconds{300};

    const auto kStarted = std::chrono::steady_clock::now();
    auto result = runBoundedProcess(request);
    const auto kElapsed = std::chrono::steady_clock::now() - kStarted;

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::VerificationFailed);
    EXPECT_LT(kElapsed, std::chrono::seconds{9}) << "the deadline did not actually stop the child";
}

// Captured output is a declared byte limit. The boundary pair is proven with
// one child whose output length is known exactly.
TEST(ProcessRunner, AppliesTheOutputByteLimitAtItsBoundary) {
    const std::string kText = "0123456789";
    auto admitted = requestFor("output_at_limit", {"-E", "echo", kText});
    // `echo` appends a line ending, which is one byte on POSIX and two on
    // Windows, so the boundary is expressed against the largest of the two.
    admitted.maximumStandardOutputBytes = kText.size() + 2U;
    EXPECT_TRUE(runBoundedProcess(admitted).has_value());

    auto rejected = requestFor("output_over_limit", {"-E", "echo", kText});
    rejected.maximumStandardOutputBytes = kText.size() - 1U;
    auto result = runBoundedProcess(rejected);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::LimitExceeded);
}

TEST(ProcessRunner, AppliesTheStandardErrorByteLimitIndependently) {
    auto request = requestFor("stderr_limit", {"-E", "no_such_subcommand"});
    request.maximumStandardErrorBytes = 1U;
    auto result = runBoundedProcess(request);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().code, FailureCode::LimitExceeded);
}

// The child must run in the requested directory rather than in whatever
// directory the test process happens to occupy.
TEST(ProcessRunner, RunsTheChildInTheRequestedWorkingDirectory) {
    auto request = requestFor("working_directory", {"-E", "cat", "marker.txt"});
    {
        std::ofstream marker(request.workingDirectory / "marker.txt", std::ios::binary | std::ios::trunc);
        marker << "found-the-working-directory";
    }
    auto result = runBoundedProcess(request);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(result->exitCode, 0);
    EXPECT_NE(result->standardOutput.find("found-the-working-directory"), std::string::npos);
}

// Capture files are created with an exclusive flag so that a stale file is
// never silently reused, and a fixed name would turn that protection into a
// race whenever two verifications of one repository overlap, which is what a
// parallel CTest run produces. Each invocation therefore owns a private leaf
// beneath the requested root and releases it on the way out.
//
// The overlap itself is proven by running the whole suite in parallel rather
// than here: creating two in-flight invocations inside one test would mean
// forking from a threaded parent, which this tool never does and which carries
// its own hazards. What is asserted here is the property that makes the overlap
// safe, namely that nothing invocation-specific is ever placed at a shared
// name.
TEST(ProcessRunner, LeavesNoInvocationStateAtTheSharedCaptureRoot) {
    const auto kDirectory = caseDirectory("shared_capture_root");
    const auto kRoot = kDirectory / "capture";
    for (int attempt = 0; attempt < 3; ++attempt) {
        ProcessRequest request{
            .executable = pinnedCMake(),
            .arguments = {"-E", "echo", "shared-root"},
            .workingDirectory = kDirectory,
            .captureDirectory = kRoot,
        };
        auto result = runBoundedProcess(request);
        ASSERT_TRUE(result.has_value()) << result.error().message;
        EXPECT_NE(result->standardOutput.find("shared-root"), std::string::npos);
    }

    ASSERT_TRUE(std::filesystem::is_directory(kRoot));
    std::vector<std::string> residue;
    for (const auto& entry : std::filesystem::directory_iterator(kRoot)) {
        residue.push_back(entry.path().filename().string());
    }
    EXPECT_TRUE(residue.empty()) << "the capture root kept " << residue.size() << " entries, starting with "
                                 << residue.front();
}

// Ambient environment is not an authority. A variable set in this process must
// not reach the child, or a workstation could change a verification result.
TEST(ProcessRunner, DoesNotLeakTheParentEnvironmentToTheChild) {
    constexpr std::string_view kMarker = "RAWFRAME_TEST_AMBIENT_MARKER";
#ifdef _WIN32
    ASSERT_EQ(_putenv("RAWFRAME_TEST_AMBIENT_MARKER=leaked-value"), 0);
#else
    ASSERT_EQ(setenv(std::string{kMarker}.c_str(), "leaked-value", 1), 0);
#endif

    auto result = runBoundedProcess(requestFor("environment", {"-E", "environment"}));
    ASSERT_TRUE(result.has_value()) << result.error().message;
#ifdef _WIN32
    // Windows needs `SystemRoot` to initialize basic APIs, so the child gets
    // exactly that one variable. Requiring a non-empty capture also keeps the
    // case from passing on a capture that never happened.
    ASSERT_FALSE(result->standardOutput.empty()) << "the child printed no environment at all";
#else
    // A POSIX child needs nothing, so it receives nothing and the exact
    // expected capture is empty. That is a measurement rather than a missing
    // result: other cases in this file already prove output capture works.
    EXPECT_TRUE(result->standardOutput.empty()) << "the child received an environment: " << result->standardOutput;
#endif
    EXPECT_EQ(result->standardOutput.find("leaked-value"), std::string::npos)
        << "the child inherited an ambient environment variable";
    EXPECT_EQ(result->standardOutput.find(kMarker), std::string::npos);
}

} // namespace rawframe::tool::evidence
