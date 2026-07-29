#pragma once

#include "failure.h"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

// Incremental SHA-256 for content that arrives in pieces, so a caller can
// enforce a byte ceiling and hash in one pass without holding the whole source.
// The provider stays behind this boundary: nothing about the underlying library
// appears in this header.
class Sha256Stream {
public:
    // The subject names the content in every failure this stream can report.
    explicit Sha256Stream(std::string subject);
    ~Sha256Stream();

    Sha256Stream(const Sha256Stream&) = delete;
    Sha256Stream& operator=(const Sha256Stream&) = delete;
    Sha256Stream(Sha256Stream&&) noexcept;
    Sha256Stream& operator=(Sha256Stream&&) noexcept;

    [[nodiscard]] Status begin();
    [[nodiscard]] Status update(std::string_view bytes);

    // Consumes the stream. Calling update or finish afterwards fails.
    [[nodiscard]] Result<std::string> finish();

private:
    struct State;
    std::unique_ptr<State> state_;
};

// The chunk both file-reading callers use. Heap-allocated at every site: a
// 1 MiB stack buffer overflows the 1 MiB default Windows thread stack.
inline constexpr std::size_t kSha256ChunkBytes = 1'048'576;

[[nodiscard]] Result<std::string> sha256File(const std::filesystem::path& path);

// The same digest over bytes already in memory, for content that was produced
// rather than read. Every entry point shares one computation, because a second
// hashing site is a second answer waiting to disagree with the first.
[[nodiscard]] Result<std::string> sha256Bytes(std::string_view bytes);

} // namespace rawframe::tool::evidence
