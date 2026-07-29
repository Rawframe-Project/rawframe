#include "process_runner.h"

#include "file_security.h"

#include <array>
#include <atomic>
#include <fstream>
#include <memory>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <Windows.h>
#else
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace rawframe::tool::evidence {

namespace {

// Two `rf-evidence` processes can verify one repository at the same time, which
// is what a parallel CTest run does, and the capture files are created with an
// exclusive flag so that a stale file is never silently reused. A fixed name
// turns that protection into a race between the two rather than isolation, so
// every invocation owns a leaf beneath the requested capture root. The name is
// the operating-system process identity plus this process's own invocation
// ordinal, which is unique without consulting a clock.
std::filesystem::path exclusiveCaptureDirectory(const std::filesystem::path& root) {
    static std::atomic<unsigned long long> invocations{0};
#ifdef _WIN32
    const auto kProcess = static_cast<unsigned long long>(GetCurrentProcessId());
#else
    const auto kProcess = static_cast<unsigned long long>(getpid());
#endif
    const auto kOrdinal = invocations.fetch_add(1, std::memory_order_relaxed);
    return root / (std::to_string(kProcess) + "-" + std::to_string(kOrdinal));
}

// The captured bytes reach the caller as strings, so the files themselves are
// working state rather than evidence. Releasing the leaf keeps a long-lived
// capture root from accumulating one directory per invocation.
class ScopedCaptureDirectory {
public:
    explicit ScopedCaptureDirectory(std::filesystem::path path) : path_(std::move(path)) {
    }
    ScopedCaptureDirectory(const ScopedCaptureDirectory&) = delete;
    ScopedCaptureDirectory& operator=(const ScopedCaptureDirectory&) = delete;
    ScopedCaptureDirectory(ScopedCaptureDirectory&&) = delete;
    ScopedCaptureDirectory& operator=(ScopedCaptureDirectory&&) = delete;

    ~ScopedCaptureDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    [[nodiscard]] const std::filesystem::path& path() const {
        return path_;
    }

private:
    std::filesystem::path path_;
};

Result<std::string> readCapture(const std::filesystem::path& path, std::size_t maximumBytes) {
    std::error_code error;
    const auto kBytes = std::filesystem::file_size(path, error);
    if (error || kBytes > maximumBytes) {
        return std::unexpected(
            Failure{FailureCode::LimitExceeded, path.generic_string(), "captured process output exceeds its limit"});
    }
    std::ifstream input(path, std::ios::binary);
    std::string output(static_cast<std::size_t>(kBytes), '\0');
    if (!output.empty()) {
        input.read(output.data(), static_cast<std::streamsize>(output.size()));
    }
    if (!input || input.gcount() != static_cast<std::streamsize>(output.size())) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, path.generic_string(), "failed to read captured process output"});
    }
    return output;
}

#ifdef _WIN32

class WindowsHandle {
public:
    explicit WindowsHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : handle_(handle) {
    }
    ~WindowsHandle() {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    WindowsHandle(const WindowsHandle&) = delete;
    WindowsHandle& operator=(const WindowsHandle&) = delete;
    WindowsHandle(WindowsHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    WindowsHandle& operator=(WindowsHandle&& other) noexcept {
        if (this != &other) {
            if (valid()) {
                CloseHandle(handle_);
            }
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept {
        return handle_;
    }
    [[nodiscard]] bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE handle_;
};

std::wstring quoteWindowsArgument(std::wstring_view argument) {
    if (argument.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        return std::wstring(argument);
    }
    std::wstring result(1, L'"');
    std::size_t backslashes = 0;
    for (const wchar_t kCharacter : argument) {
        if (kCharacter == L'\\') {
            ++backslashes;
        } else if (kCharacter == L'"') {
            result.append((backslashes * 2) + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
        } else {
            result.append(backslashes, L'\\');
            backslashes = 0;
            result.push_back(kCharacter);
        }
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

Result<ProcessResult> runWindowsProcess(const ProcessRequest& request) {
    std::error_code error;
    std::filesystem::create_directories(request.captureDirectory, error);
    if (error) {
        return std::unexpected(Failure{
            FailureCode::IoFailure, request.captureDirectory.generic_string(), "failed to create capture directory"});
    }
    const auto kStdoutPath = request.captureDirectory / "stdout.tmp";
    const auto kStderrPath = request.captureDirectory / "stderr.tmp";
    std::filesystem::remove(kStdoutPath, error);
    error.clear();
    std::filesystem::remove(kStderrPath, error);

    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    WindowsHandle stdoutHandle(CreateFileW(kStdoutPath.c_str(),
                                           GENERIC_WRITE,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           &security,
                                           CREATE_NEW,
                                           FILE_ATTRIBUTE_TEMPORARY,
                                           nullptr));
    WindowsHandle stderrHandle(CreateFileW(kStderrPath.c_str(),
                                           GENERIC_WRITE,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           &security,
                                           CREATE_NEW,
                                           FILE_ATTRIBUTE_TEMPORARY,
                                           nullptr));
    WindowsHandle stdinHandle(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, &security, OPEN_EXISTING, 0, nullptr));
    if (!stdoutHandle.valid() || !stderrHandle.valid() || !stdinHandle.valid()) {
        return std::unexpected(Failure{FailureCode::IoFailure,
                                       request.captureDirectory.generic_string(),
                                       "failed to create process capture handles"});
    }

    std::wstring commandLine = quoteWindowsArgument(request.executable.wstring());
    for (const auto& argument : request.arguments) {
        commandLine.push_back(L' ');
        commandLine += quoteWindowsArgument(std::filesystem::path(argument).wstring());
    }
    commandLine.push_back(L'\0');

    WindowsHandle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                              JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_PROCESS_TIME;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = 10LL * 10'000'000LL;
    limits.ProcessMemoryLimit = request.maximumPrivateMemoryBytes;
    if (!job.valid() ||
        (SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) == 0)) {
        return std::unexpected(Failure{FailureCode::VerificationFailed,
                                       request.executable.generic_string(),
                                       "failed to configure child-process limits"});
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = stdinHandle.get();
    startup.hStdOutput = stdoutHandle.get();
    startup.hStdError = stderrHandle.get();
    PROCESS_INFORMATION process{};
    std::array<wchar_t, MAX_PATH> windowsDirectory{};
    const auto kWindowsLength =
        GetWindowsDirectoryW(windowsDirectory.data(), static_cast<UINT>(windowsDirectory.size()));
    std::wstring environment = L"SystemRoot=";
    environment.append(windowsDirectory.data(), kWindowsLength);
    environment.append(2, L'\0');

    if (CreateProcessW(request.executable.c_str(),
                       commandLine.data(),
                       nullptr,
                       nullptr,
                       TRUE,
                       CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                       environment.data(),
                       request.workingDirectory.c_str(),
                       &startup,
                       &process) == 0) {
        return std::unexpected(Failure{
            FailureCode::VerificationFailed, request.executable.generic_string(), "failed to create child process"});
    }
    WindowsHandle processHandle(process.hProcess);
    WindowsHandle threadHandle(process.hThread);
    if ((AssignProcessToJobObject(job.get(), processHandle.get()) == 0) ||
        ResumeThread(threadHandle.get()) == static_cast<DWORD>(-1)) {
        TerminateProcess(processHandle.get(), 1);
        return std::unexpected(Failure{FailureCode::VerificationFailed,
                                       request.executable.generic_string(),
                                       "failed to constrain or resume child process"});
    }

    const auto kDeadline = std::chrono::steady_clock::now() + request.timeout;
    while (WaitForSingleObject(processHandle.get(), 25) == WAIT_TIMEOUT) {
        if (std::chrono::steady_clock::now() >= kDeadline) {
            TerminateJobObject(job.get(), 1);
            return std::unexpected(Failure{
                FailureCode::VerificationFailed, request.executable.generic_string(), "child process timed out"});
        }
        const auto kStdoutBytes = std::filesystem::file_size(kStdoutPath, error);
        error.clear();
        const auto kStderrBytes = std::filesystem::file_size(kStderrPath, error);
        if (kStdoutBytes > request.maximumStandardOutputBytes || kStderrBytes > request.maximumStandardErrorBytes) {
            TerminateJobObject(job.get(), 1);
            return std::unexpected(Failure{FailureCode::LimitExceeded,
                                           request.executable.generic_string(),
                                           "child process output exceeded its limit"});
        }
    }

    DWORD exitCode = 0;
    if (GetExitCodeProcess(processHandle.get(), &exitCode) == 0) {
        return std::unexpected(Failure{
            FailureCode::VerificationFailed, request.executable.generic_string(), "failed to read child exit code"});
    }
    stdoutHandle = WindowsHandle();
    stderrHandle = WindowsHandle();
    auto standardOutput = readCapture(kStdoutPath, request.maximumStandardOutputBytes);
    auto standardError = readCapture(kStderrPath, request.maximumStandardErrorBytes);
    std::filesystem::remove(kStdoutPath, error);
    error.clear();
    std::filesystem::remove(kStderrPath, error);
    if (!standardOutput || !standardError) {
        return std::unexpected(!standardOutput ? standardOutput.error() : standardError.error());
    }
    return ProcessResult{static_cast<int>(exitCode), std::move(*standardOutput), std::move(*standardError)};
}

#else

Result<ProcessResult> runPosixProcess(const ProcessRequest& request) {
    std::error_code error;
    std::filesystem::create_directories(request.captureDirectory, error);
    const auto kStdoutPath = request.captureDirectory / "stdout.tmp";
    const auto kStderrPath = request.captureDirectory / "stderr.tmp";
    std::filesystem::remove(kStdoutPath, error);
    error.clear();
    std::filesystem::remove(kStderrPath, error);
    // No O_CLOEXEC: these descriptors are handed to the child deliberately.
    const int kStdoutFile = openExclusiveOwnerOnly(kStdoutPath.c_str(), 0);
    const int kStderrFile = openExclusiveOwnerOnly(kStderrPath.c_str(), 0);
    if (kStdoutFile < 0 || kStderrFile < 0) {
        if (kStdoutFile >= 0) {
            close(kStdoutFile);
        }
        if (kStderrFile >= 0) {
            close(kStderrFile);
        }
        return std::unexpected(Failure{
            FailureCode::IoFailure, request.captureDirectory.generic_string(), "failed to create capture files"});
    }

    std::vector<char*> arguments;
    auto executable = request.executable.string();
    arguments.push_back(executable.data());
    std::vector<std::string> ownedArguments = request.arguments;
    for (auto& argument : ownedArguments) {
        arguments.push_back(argument.data());
    }
    arguments.push_back(nullptr);

    const pid_t kProcess = fork();
    if (kProcess == 0) {
        setpgid(0, 0);
        dup2(kStdoutFile, STDOUT_FILENO);
        dup2(kStderrFile, STDERR_FILENO);
        close(kStdoutFile);
        close(kStderrFile);
        // The data segment, not the address space. The request bounds the memory
        // a child actually uses, which is what the Windows job object counts,
        // and RLIMIT_AS instead counts address space a child merely reserves.
        // A Go runtime reserves far more than it commits, so an address-space
        // limit of this size stops every Go-based prepared tool from starting
        // at all while permitting one that quietly commits the same amount.
        const rlimit kMemoryLimit{request.maximumPrivateMemoryBytes, request.maximumPrivateMemoryBytes};
        const rlimit kCpuLimit{10, 10};
        setrlimit(RLIMIT_DATA, &kMemoryLimit);
        setrlimit(RLIMIT_CPU, &kCpuLimit);
        chdir(request.workingDirectory.c_str());
        clearenv();
        execv(request.executable.c_str(), arguments.data());
        _exit(127);
    }
    close(kStdoutFile);
    close(kStderrFile);
    if (kProcess < 0) {
        return std::unexpected(Failure{
            FailureCode::VerificationFailed, request.executable.generic_string(), "failed to fork child kProcess"});
    }

    const auto kDeadline = std::chrono::steady_clock::now() + request.timeout;
    int status = 0;
    while (waitpid(kProcess, &status, WNOHANG) == 0) {
        if (std::chrono::steady_clock::now() >= kDeadline) {
            kill(-kProcess, SIGKILL);
            waitpid(kProcess, &status, 0);
            return std::unexpected(Failure{
                FailureCode::VerificationFailed, request.executable.generic_string(), "child kProcess timed out"});
        }
        const auto kStdoutBytes = std::filesystem::file_size(kStdoutPath, error);
        error.clear();
        const auto kStderrBytes = std::filesystem::file_size(kStderrPath, error);
        if (kStdoutBytes > request.maximumStandardOutputBytes || kStderrBytes > request.maximumStandardErrorBytes) {
            kill(-kProcess, SIGKILL);
            waitpid(kProcess, &status, 0);
            return std::unexpected(Failure{FailureCode::LimitExceeded,
                                           request.executable.generic_string(),
                                           "child kProcess output exceeded its limit"});
        }
        usleep(25'000);
    }
    if (!WIFEXITED(status)) {
        return std::unexpected(Failure{FailureCode::VerificationFailed,
                                       request.executable.generic_string(),
                                       "child kProcess terminated abnormally"});
    }
    auto standardOutput = readCapture(kStdoutPath, request.maximumStandardOutputBytes);
    auto standardError = readCapture(kStderrPath, request.maximumStandardErrorBytes);
    std::filesystem::remove(kStdoutPath, error);
    error.clear();
    std::filesystem::remove(kStderrPath, error);
    if (!standardOutput || !standardError) {
        return std::unexpected(!standardOutput ? standardOutput.error() : standardError.error());
    }
    return ProcessResult{WEXITSTATUS(status), std::move(*standardOutput), std::move(*standardError)};
}

#endif

} // namespace

Result<ProcessResult> runBoundedProcess(const ProcessRequest& request) {
    if (!request.executable.is_absolute() || !std::filesystem::is_regular_file(request.executable)) {
        return std::unexpected(Failure{FailureCode::MissingInput,
                                       request.executable.generic_string(),
                                       "child executable must be an existing absolute path"});
    }
    const ScopedCaptureDirectory kCapture(exclusiveCaptureDirectory(request.captureDirectory));
    ProcessRequest scoped = request;
    scoped.captureDirectory = kCapture.path();
#ifdef _WIN32
    return runWindowsProcess(scoped);
#else
    return runPosixProcess(scoped);
#endif
}

} // namespace rawframe::tool::evidence
