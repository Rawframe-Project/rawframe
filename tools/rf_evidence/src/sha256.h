#pragma once

#include "failure.h"

#include <filesystem>
#include <string>
#include <string_view>

namespace rawframe::tool::evidence {

[[nodiscard]] Result<std::string> sha256File(const std::filesystem::path& path);

// The same digest over bytes already in memory, for content that was produced
// rather than read. Both entry points share one computation, because a second
// hashing site is a second answer waiting to disagree with the first.
[[nodiscard]] Result<std::string> sha256Bytes(std::string_view bytes);

} // namespace rawframe::tool::evidence
