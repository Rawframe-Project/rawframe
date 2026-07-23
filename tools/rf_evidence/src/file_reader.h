#pragma once

#include "failure.h"

#include <cstddef>
#include <filesystem>
#include <simdjson.h>

namespace rawframe::tool::evidence {

inline constexpr std::size_t kMaximumMaintainedJsonBytes = 1'048'576;

[[nodiscard]] Result<simdjson::padded_string> readBoundedFile(const std::filesystem::path& path,
                                                              std::size_t maximumBytes = kMaximumMaintainedJsonBytes);

} // namespace rawframe::tool::evidence
