#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

namespace rawframe::tool::evidence {

int runCommand(std::span<const std::string_view> arguments, std::ostream& output, std::ostream& errors);

} // namespace rawframe::tool::evidence
