#pragma once

#include "failure.h"

#include <filesystem>

namespace rawframe::tool::evidence {

[[nodiscard]] Status validateJsonAdmission(const std::filesystem::path& path);

} // namespace rawframe::tool::evidence
