#include "file_security.h"

#include <string>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <Windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace rawframe::tool::evidence {

namespace {

#ifdef _WIN32

std::string describeLastError(unsigned long code) {
    return "operating-system error " + std::to_string(code);
}

#else

std::string describeErrno(int code) {
    // strerror is not thread safe and strerror_r has two incompatible
    // signatures across libc versions. The numeric code is unambiguous and this
    // tool never localizes a diagnostic.
    return "errno " + std::to_string(code);
}

#endif

} // namespace

Result<FileKind> classifyPath(const std::filesystem::path& path) {
#ifdef _WIN32
    // GetFileAttributesW reports the reparse attribute directly rather than
    // resolving the link. std::filesystem::is_symlink is not used here because
    // the standard library's treatment of junctions is an implementation
    // extension, and a junction is the form of indirection an unprivileged
    // process can actually create on Windows.
    const DWORD kAttributes = GetFileAttributesW(path.c_str());
    if (kAttributes == INVALID_FILE_ATTRIBUTES) {
        const DWORD kError = GetLastError();
        if (kError == ERROR_FILE_NOT_FOUND || kError == ERROR_PATH_NOT_FOUND || kError == ERROR_INVALID_NAME ||
            kError == ERROR_BAD_NETPATH || kError == ERROR_NOT_READY) {
            return FileKind::Missing;
        }
        return std::unexpected(Failure{FailureCode::IoFailure, path.generic_string(), describeLastError(kError)});
    }
    if ((kAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) {
        return FileKind::Reparse;
    }
    if ((kAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) {
        return FileKind::Directory;
    }
    if ((kAttributes & FILE_ATTRIBUTE_DEVICE) != 0U) {
        return FileKind::Special;
    }
    return FileKind::Regular;
#else
    std::error_code error;
    const auto kStatus = std::filesystem::symlink_status(path, error);
    if (error) {
        if (kStatus.type() == std::filesystem::file_type::not_found) {
            return FileKind::Missing;
        }
        return std::unexpected(Failure{FailureCode::IoFailure, path.generic_string(), error.message()});
    }
    switch (kStatus.type()) {
    case std::filesystem::file_type::not_found:
        return FileKind::Missing;
    case std::filesystem::file_type::symlink:
        return FileKind::Reparse;
    case std::filesystem::file_type::directory:
        return FileKind::Directory;
    case std::filesystem::file_type::regular:
        return FileKind::Regular;
    default:
        return FileKind::Special;
    }
#endif
}

struct ExclusiveFile::State {
#ifdef _WIN32
    HANDLE handle = INVALID_HANDLE_VALUE;
#else
    int descriptor = -1;
#endif
    std::string subject;
};

ExclusiveFile::ExclusiveFile() : state_(std::make_unique<State>()) {
}

ExclusiveFile::~ExclusiveFile() {
    if (state_) {
        // The result cannot be reported from a destructor. A caller that needs
        // to know whether the bytes reached the file calls close explicitly,
        // and every caller in this tool does.
        releaseHandle();
    }
}

ExclusiveFile::ExclusiveFile(ExclusiveFile&&) noexcept = default;
ExclusiveFile& ExclusiveFile::operator=(ExclusiveFile&&) noexcept = default;

bool ExclusiveFile::isOpen() const {
#ifdef _WIN32
    return state_ && state_->handle != INVALID_HANDLE_VALUE;
#else
    return state_ && state_->descriptor >= 0;
#endif
}

Status ExclusiveFile::create(const std::filesystem::path& path) {
    if (isOpen()) {
        return std::unexpected(
            Failure{FailureCode::IoFailure, path.generic_string(), "the file handle is already open"});
    }
    state_->subject = path.generic_string();

#ifdef _WIN32
    // CREATE_NEW fails when the path exists. No sharing, so nothing else can
    // open the staged file while it is being written.
    state_->handle = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (state_->handle == INVALID_HANDLE_VALUE) {
        const DWORD kError = GetLastError();
        if (kError == ERROR_FILE_EXISTS || kError == ERROR_ALREADY_EXISTS) {
            return std::unexpected(
                Failure{FailureCode::OwnershipCollision, state_->subject, "the path already exists"});
        }
        return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, describeLastError(kError)});
    }
#else
    // O_EXCL fails when the path exists and does not follow a final symbolic
    // link, so a link planted at the staged name cannot redirect the write.
    // The mode is applied at creation, so the file is never more permissive
    // than owner read and write, not even briefly.
    constexpr int kFlags = O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC;
    constexpr mode_t kOwnerOnly = S_IRUSR | S_IWUSR;
    state_->descriptor = ::open(path.c_str(), kFlags, kOwnerOnly);
    if (state_->descriptor < 0) {
        const int kError = errno;
        if (kError == EEXIST) {
            return std::unexpected(
                Failure{FailureCode::OwnershipCollision, state_->subject, "the path already exists"});
        }
        return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, describeErrno(kError)});
    }
#endif
    return {};
}

Status ExclusiveFile::write(std::string_view bytes) {
    if (!isOpen()) {
        return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, "the file handle is not open"});
    }
    if (bytes.empty()) {
        return {};
    }

    std::size_t written = 0;
    while (written < bytes.size()) {
        const std::size_t kRemaining = bytes.size() - written;
#ifdef _WIN32
        constexpr std::size_t kMaximumChunk = 0x7FFF0000U;
        const auto kChunk = static_cast<DWORD>(kRemaining < kMaximumChunk ? kRemaining : kMaximumChunk);
        DWORD produced = 0;
        if (WriteFile(state_->handle, bytes.data() + written, kChunk, &produced, nullptr) == 0) {
            return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, describeLastError(GetLastError())});
        }
        if (produced == 0) {
            return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, "the write made no progress"});
        }
        written += static_cast<std::size_t>(produced);
#else
        const auto kProduced = ::write(state_->descriptor, bytes.data() + written, kRemaining);
        if (kProduced < 0) {
            const int kError = errno;
            if (kError == EINTR) {
                continue;
            }
            return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, describeErrno(kError)});
        }
        if (kProduced == 0) {
            return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, "the write made no progress"});
        }
        written += static_cast<std::size_t>(kProduced);
#endif
    }
    return {};
}

void ExclusiveFile::releaseHandle() noexcept {
    if (!isOpen()) {
        return;
    }
#ifdef _WIN32
    CloseHandle(state_->handle);
    state_->handle = INVALID_HANDLE_VALUE;
#else
    ::close(state_->descriptor);
    state_->descriptor = -1;
#endif
}

Status ExclusiveFile::close() {
    if (!isOpen()) {
        return {};
    }
#ifdef _WIN32
    const BOOL kClosed = CloseHandle(state_->handle);
    state_->handle = INVALID_HANDLE_VALUE;
    if (kClosed == 0) {
        return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, describeLastError(GetLastError())});
    }
#else
    const int kClosed = ::close(state_->descriptor);
    state_->descriptor = -1;
    if (kClosed != 0) {
        return std::unexpected(Failure{FailureCode::IoFailure, state_->subject, describeErrno(errno)});
    }
#endif
    return {};
}

Status publishWithoutReplacement(const std::filesystem::path& staged, const std::filesystem::path& destination) {
#ifdef _WIN32
    // MOVEFILE_REPLACE_EXISTING is deliberately absent: without it the move
    // fails when the destination exists, which is the behavior an immutable
    // store needs.
    if (MoveFileExW(staged.c_str(), destination.c_str(), 0) == 0) {
        const DWORD kError = GetLastError();
        if (kError == ERROR_FILE_EXISTS || kError == ERROR_ALREADY_EXISTS) {
            return std::unexpected(Failure{
                FailureCode::OwnershipCollision, destination.generic_string(), "the destination already exists"});
        }
        return std::unexpected(
            Failure{FailureCode::IoFailure, destination.generic_string(), describeLastError(kError)});
    }
#else
    // link fails with EEXIST when the destination exists, which rename does
    // not: rename(2) replaces silently. The staged name survives until the
    // unlink below, and it is never blob shaped, so a failure between the two
    // leaves an inert file rather than a second reachable copy.
    if (::link(staged.c_str(), destination.c_str()) != 0) {
        const int kError = errno;
        if (kError == EEXIST) {
            return std::unexpected(Failure{
                FailureCode::OwnershipCollision, destination.generic_string(), "the destination already exists"});
        }
        return std::unexpected(Failure{FailureCode::IoFailure, destination.generic_string(), describeErrno(kError)});
    }
    if (::unlink(staged.c_str()) != 0) {
        return std::unexpected(Failure{FailureCode::IoFailure, staged.generic_string(), describeErrno(errno)});
    }
#endif
    return {};
}

} // namespace rawframe::tool::evidence
