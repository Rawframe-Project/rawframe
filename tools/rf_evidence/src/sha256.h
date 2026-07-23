#pragma once

#include "failure.h"

#include <filesystem>
#include <string>

namespace rawframe::tool::evidence {

[[nodiscard]] Result<std::string> sha256File(const std::filesystem::path& path);

} // namespace rawframe::tool::evidence
