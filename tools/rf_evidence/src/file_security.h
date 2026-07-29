#pragma once

#include "failure.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>

namespace rawframe::tool::evidence {

// What a path names, determined without following indirection. A store that
// resolved first and classified afterwards would inspect the target and miss
// exactly the case it is trying to reject.
enum class FileKind : std::uint8_t {
    Missing,
    Regular,
    Directory,
    // A symbolic link on any host, and additionally a junction, mount point, or
    // any other reparse point on Windows. One value, because a store treats
    // every form of indirection identically: it refuses it.
    Reparse,
    // A FIFO, socket, device, or anything else that is not ordinary content.
    Special,
};

[[nodiscard]] constexpr const char* fileKindName(FileKind kind) noexcept {
    switch (kind) {
    case FileKind::Missing:
        return "missing";
    case FileKind::Regular:
        return "regular file";
    case FileKind::Directory:
        return "directory";
    case FileKind::Reparse:
        return "symbolic link or reparse point";
    case FileKind::Special:
        return "special file";
    }
    return "unknown";
}

[[nodiscard]] Result<FileKind> classifyPath(const std::filesystem::path& path);

#ifndef _WIN32
// Exclusive owner-only creation through POSIX open, which is the only variadic
// call in this repository.
//
// POSIX declares open variadic because the creation mode is read only when
// O_CREAT is set, and offers no non-variadic equivalent that takes a mode, so
// the call cannot be avoided. Routing every caller through one function keeps
// the single suppression of cppcoreguidelines-pro-type-vararg, and the reason
// for it, in one reviewable place instead of once per call site.
//
// Calling open through a non-variadic function pointer would silence the check
// with no suppression at all. It is rejected deliberately: the x86-64 call
// sequences for variadic and non-variadic functions differ, so that trade buys
// a clean lint report with undefined behavior, which is the worse of the two.
//
// `extraFlags` is OR-ed into the fixed creation flags. A caller that must not
// leak the descriptor across an exec passes O_CLOEXEC; a caller deliberately
// handing the descriptor to a child passes 0.
[[nodiscard]] int openExclusiveOwnerOnly(const char* path, int extraFlags) noexcept;
#endif

// A file created exclusively: the create fails when the path already exists,
// rather than truncating whatever was there. POSIX creates it at mode 0600, so
// there is no window in which it is more permissive. Windows creates it with no
// sharing, so no other handle can open it while it is being written.
class ExclusiveFile {
public:
    ExclusiveFile();
    ~ExclusiveFile();

    ExclusiveFile(const ExclusiveFile&) = delete;
    ExclusiveFile& operator=(const ExclusiveFile&) = delete;
    ExclusiveFile(ExclusiveFile&&) noexcept;
    ExclusiveFile& operator=(ExclusiveFile&&) noexcept;

    // Fails with OwnershipCollision when the path already exists, which is the
    // signal a caller retries under a different name.
    [[nodiscard]] Status create(const std::filesystem::path& path);
    [[nodiscard]] Status write(std::string_view bytes);

    // Flushes and closes.
    [[nodiscard]] Status close();

    [[nodiscard]] bool isOpen() const;

private:
    // Closes without producing a result, for the destructor, which has nowhere
    // to report one. Every explicit caller goes through close above and must
    // handle what it returns.
    void releaseHandle() noexcept;

    struct State;
    std::unique_ptr<State> state_;
};

// Moves a staged file onto its final path and fails if that path already
// exists, which the ordinary rename does not: both std::filesystem::rename and
// POSIX rename(2) replace the destination silently. An immutable store needs
// the opposite, so this is a link plus unlink on POSIX and a MoveFileExW
// without MOVEFILE_REPLACE_EXISTING on Windows. Both are atomic with respect to
// the destination: it either does not exist or is the complete published file.
[[nodiscard]] Status publishWithoutReplacement(const std::filesystem::path& staged,
                                               const std::filesystem::path& destination);

} // namespace rawframe::tool::evidence
