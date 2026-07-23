#include "process_runner.h"

#include <array>
#include <fstream>
#include <memory>
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
    const auto stdoutPath = request.captureDirectory / "stdout.tmp";
    const auto stderrPath = request.captureDirectory / "stderr.tmp";
    std::filesystem::remove(stdoutPath, error);
    error.clear();
    std::filesystem::remove(stderrPath, error);
    const int stdoutFile = open(stdoutPath.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    const int stderrFile = open(stderrPath.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (stdoutFile < 0 || stderrFile < 0) {
        if (stdoutFile >= 0)
            close(stdoutFile);
        if (stderrFile >= 0)
            close(stderrFile);
        return std::unexpected(Failure{
            FailureCode::IoFailure, request.captureDirectory.generic_string(), "failed to create capture files"});
    }

    std::vector<char*> arguments;
    auto executable = request.executable.string();
    arguments.push_back(executable.data());
    std::vector<std::string> ownedArguments = request.arguments;
    for (auto& argument : ownedArguments)
        arguments.push_back(argument.data());
    arguments.push_back(nullptr);

    const pid_t process = fork();
    if (process == 0) {
        setpgid(0, 0);
        dup2(stdoutFile, STDOUT_FILENO);
        dup2(stderrFile, STDERR_FILENO);
        close(stdoutFile);
        close(stderrFile);
        const rlimit memoryLimit{request.maximumPrivateMemoryBytes, request.maximumPrivateMemoryBytes};
        const rlimit cpuLimit{10, 10};
        setrlimit(RLIMIT_AS, &memoryLimit);
        setrlimit(RLIMIT_CPU, &cpuLimit);
        chdir(request.workingDirectory.c_str());
        clearenv();
        execv(request.executable.c_str(), arguments.data());
        _exit(127);
    }
    close(stdoutFile);
    close(stderrFile);
    if (process < 0) {
        return std::unexpected(Failure{
            FailureCode::VerificationFailed, request.executable.generic_string(), "failed to fork child process"});
    }

    const auto deadline = std::chrono::steady_clock::now() + request.timeout;
    int status = 0;
    while (waitpid(process, &status, WNOHANG) == 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            kill(-process, SIGKILL);
            waitpid(process, &status, 0);
            return std::unexpected(Failure{
                FailureCode::VerificationFailed, request.executable.generic_string(), "child process timed out"});
        }
        const auto stdoutBytes = std::filesystem::file_size(stdoutPath, error);
        error.clear();
        const auto stderrBytes = std::filesystem::file_size(stderrPath, error);
        if (stdoutBytes > request.maximumStandardOutputBytes || stderrBytes > request.maximumStandardErrorBytes) {
            kill(-process, SIGKILL);
            waitpid(process, &status, 0);
            return std::unexpected(Failure{FailureCode::LimitExceeded,
                                           request.executable.generic_string(),
                                           "child process output exceeded its limit"});
        }
        usleep(25'000);
    }
    if (!WIFEXITED(status)) {
        return std::unexpected(Failure{FailureCode::VerificationFailed,
                                       request.executable.generic_string(),
                                       "child process terminated abnormally"});
    }
    auto standardOutput = readCapture(stdoutPath, request.maximumStandardOutputBytes);
    auto standardError = readCapture(stderrPath, request.maximumStandardErrorBytes);
    std::filesystem::remove(stdoutPath, error);
    error.clear();
    std::filesystem::remove(stderrPath, error);
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
#ifdef _WIN32
    return runWindowsProcess(request);
#else
    return runPosixProcess(request);
#endif
}

} // namespace rawframe::tool::evidence
